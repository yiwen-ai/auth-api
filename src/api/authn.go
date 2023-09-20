package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/key"
	_ "github.com/ldclabs/cose/key/hmac"
	"github.com/mssola/useragent"
	"github.com/teambition/gear"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"

	"github.com/yiwen-ai/auth-api/src/bll"
	"github.com/yiwen-ai/auth-api/src/conf"
	"github.com/yiwen-ai/auth-api/src/logging"
	"github.com/yiwen-ai/auth-api/src/util"
)

type AuthN struct {
	blls       *bll.Blls
	providers  map[string]*oauth2.Config
	stateMACer key.MACer
	cookie     conf.Cookie
	authURL    *conf.AuthURL
}

func NewAuth(blls *bll.Blls, cfg *conf.ConfigTpl) *AuthN {
	macer, err := cfg.COSEKeys.Oauth2State.MACer()
	if err != nil {
		panic(err)
	}

	authn := &AuthN{
		blls:       blls,
		providers:  make(map[string]*oauth2.Config),
		stateMACer: macer,
		cookie:     cfg.Cookie,
		authURL:    &cfg.AuthURL,
	}

	for k, v := range cfg.Providers {
		var endpoint oauth2.Endpoint
		switch k {
		case "github":
			endpoint = endpoints.GitHub
		case "wechat":
			endpoint = oauth2.Endpoint{
				AuthURL:  "https://open.weixin.qq.com/connect/qrconnect",
				TokenURL: "https://api.weixin.qq.com/sns/oauth2/access_token",
			}
		case "wechat_h5":
			endpoint = oauth2.Endpoint{
				AuthURL:  "https://open.weixin.qq.com/connect/oauth2/authorize",
				TokenURL: "https://api.weixin.qq.com/sns/oauth2/access_token",
			}
		case "google":
			endpoint = endpoints.Google
		default:
			panic(fmt.Sprintf("unknown provider %q\n", k))
		}

		authn.providers[k] = &oauth2.Config{
			ClientID:     v.ClientID,
			ClientSecret: v.ClientSecret,
			Scopes:       v.Scopes,
			RedirectURL:  v.RedirectURL,
			Endpoint:     endpoint,
		}
	}

	return authn
}

func (a *AuthN) Login(ctx *gear.Context) error {
	idp := ctx.Param("idp")
	xid := ctx.GetHeader(gear.HeaderXRequestID)

	nextURL, ok := a.authURL.CheckNextUrl(ctx.Query("next_url"))
	if !ok {
		next := a.authURL.GenNextUrl(&nextURL, 400, xid)
		logging.SetTo(ctx, "error", fmt.Sprintf("invalid next_url %q", ctx.Query("next_url")))
		return ctx.Redirect(next)
	}

	provider, ok := a.providers[idp]
	if !ok {
		next := a.authURL.GenNextUrl(&nextURL, 400, xid)
		logging.SetTo(ctx, "error", fmt.Sprintf("unknown provider %q", idp))
		return ctx.Redirect(next)
	}

	state, err := a.createState(idp, provider.ClientID, nextURL.String())
	if err != nil {
		next := a.authURL.GenNextUrl(&nextURL, 500, xid)
		logging.SetTo(ctx, "error", fmt.Sprintf("failed to create state: %v", err))
		return ctx.Redirect(next)
	}

	url := a.getAuthCodeURL(idp, state)
	return ctx.Redirect(url)
}

// Get ..
func (a *AuthN) Callback(ctx *gear.Context) error {
	idp := ctx.Param("idp")
	xid := ctx.GetHeader(gear.HeaderXRequestID)

	provider, ok := a.providers[idp]
	if !ok {
		next := a.authURL.GenNextUrl(nil, 400, xid)
		logging.SetTo(ctx, "error", fmt.Sprintf("unknown provider %q", idp))
		return ctx.Redirect(next)
	}

	code := ctx.Query("code")
	state := ctx.Query("state")
	nextURL, err := a.verifyState(idp, provider.ClientID, state)
	if err != nil {
		next := a.authURL.GenNextUrl(nil, 403, xid)
		logging.SetTo(ctx, "error", fmt.Sprintf("invalid state: %v", err))
		return ctx.Redirect(next)
	}

	input, err := a.exchange(ctx, idp, code)
	if err != nil {
		next := a.authURL.GenNextUrl(nextURL, 403, xid)
		logging.SetTo(ctx, "error", err.Error())
		return ctx.Redirect(next)
	}

	if input.User.Name == "" {
		input.User.Name = input.Sub
	}

	input.Idp = idp
	input.Aud = provider.ClientID
	input.ExpiresIn = a.cookie.ExpiresIn
	input.Scope = provider.Scopes
	input.Ip = ctx.IP().String()
	locale := ctx.AcceptLanguage()
	if i := strings.IndexAny(locale, "-_"); i > 0 {
		locale = locale[:i]
	}
	input.User.Locale = locale
	input.DeviceID = ctx.GetHeader("X-Device-Id")
	didCookieName := a.cookie.NamePrefix + "_DID"
	if input.DeviceID == "" {
		if cookie, _ := ctx.Req.Cookie(didCookieName); cookie != nil {
			input.DeviceID = cookie.Value
		}
	}

	ua := useragent.New(ctx.GetHeader(gear.HeaderUserAgent))
	desc := make([]string, 0, 4)
	if v := ua.Model(); v != "" {
		desc = append(desc, v)
	}
	if v := ua.Platform(); v != "" {
		desc = append(desc, v)
	}
	if v := ua.OS(); v != "" {
		desc = append(desc, v)
	}
	if n, v := ua.Browser(); n != "" && v != "" {
		desc = append(desc, n, v)
	}
	input.DeviceDesc = strings.Join(desc, ", ")

	switch idp {
	case "wechat":
		if coIdp, ok := a.providers["wechat_h5"]; ok {
			input.CoAuthN = &bll.AuthNPK{
				Idp: "wechat_h5",
				Aud: coIdp.ClientID,
				Sub: input.Sub,
			}
		}
	case "wechat_h5":
		if coIdp, ok := a.providers["wechat"]; ok {
			input.CoAuthN = &bll.AuthNPK{
				Idp: "wechat",
				Aud: coIdp.ClientID,
				Sub: input.Sub,
			}
		}
	}

	res, err := a.blls.AuthN.LoginOrNew(ctx, input)
	if err != nil {
		next := a.authURL.GenNextUrl(nextURL, 500, xid)
		logging.SetTo(ctx, "error", fmt.Sprintf("AuthN.LoginOrNew failed: %v", err))
		return ctx.Redirect(next)
	}

	// give award for registration
	if res.UserCreatedAt > 0 {
		referrer := ""
		if c, _ := ctx.Req.Cookie("by"); c != nil {
			referrer = c.Value
		}
		go a.giveAward(conf.WithGlobalCtx(ctx), res.UID, referrer)
		a.blls.Logbase.Log(ctx, bll.LogActionSysCreateUser, 1, res.UID, res.UID, &bll.LogPayload{
			Idp: util.Ptr(idp),
			Sub: util.Ptr(input.Sub),
		})

		// disable user registration in yiwen.ltd
		if conf.Config.Env != "prod" {
			if _, err = a.blls.Session.DisabledUser(ctx, res.UID); err != nil {
				logging.SetTo(ctx, "error", fmt.Sprintf("DisabledUser failed: %v", err))
			}
		}
	} else {
		a.blls.Logbase.Log(ctx, bll.LogActionUserLogin, 1, res.UID, res.UID, &bll.LogPayload{
			Idp: util.Ptr(idp),
			Sub: util.Ptr(input.Sub),
		})
	}

	didCookie := &http.Cookie{
		Name:     didCookieName,
		Value:    res.SID.String(),
		HttpOnly: true,
		Secure:   a.cookie.Secure,
		MaxAge:   3600 * 24 * 366,
		Path:     "/",
		Domain:   a.cookie.Domain,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(ctx.Res, didCookie)

	sessCookie := &http.Cookie{
		Name:     a.cookie.NamePrefix + "_SESS",
		Value:    res.Session,
		HttpOnly: true,
		Secure:   a.cookie.Secure,
		MaxAge:   int(a.cookie.ExpiresIn),
		Path:     "/",
		Domain:   a.cookie.Domain,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(ctx.Res, sessCookie)
	next := a.authURL.GenNextUrl(nextURL, 200, "")

	return ctx.Redirect(next)
}

func (a *AuthN) giveAward(gctx context.Context, uid util.ID, referrer string) {
	conf.Config.ObtainJob()
	defer conf.Config.ReleaseJob()

	wallet, err := a.blls.Walletbase.Get(gctx, uid)
	if wallet != nil && wallet.Sequence == 0 {
		var u *bll.UserInfo
		input := &bll.AwardPayload{}
		if u, err = a.blls.Session.UserInfo(gctx, util.TryParseID(referrer), referrer); err == nil {
			input.Referrer = u.ID
		}
		_, err = a.blls.Walletbase.AwardRegistration(gctx, uid, input)
	}

	if err != nil {
		logging.Errf("giveAward to %s error: %v", uid.String(), err)
	}
}

func (a *AuthN) getAuthCodeURL(idp, state string) string {
	provider := a.providers[idp]
	uri := provider.AuthCodeURL(state)
	switch idp {
	case "wechat", "wechat_h5":
		// https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html
		uri = strings.Replace(uri, "client_id", "appid", 1)
		uri += "#wechat_redirect"
	}

	return uri
}

func (a *AuthN) exchange(ctx context.Context, idp, code string) (*bll.AuthNInput, error) {
	cli := util.ExternalHTTPClient
	cctx := context.WithValue(ctx, oauth2.HTTPClient, cli)
	provider := a.providers[idp]
	rt := &bll.AuthNInput{}

	switch idp {
	case "wechat", "wechat_h5":
		v := url.Values{
			"appid":      {provider.ClientID},
			"secret":     {provider.ClientSecret},
			"code":       {code},
			"grant_type": {"authorization_code"},
		}
		// https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html
		// https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html
		uri := provider.Endpoint.TokenURL + "?" + v.Encode()

		type wechatToken struct {
			AccessToken  string `json:"access_token" cbor:"access_token"`
			RefreshToken string `json:"refresh_token,omitempty" cbor:"refresh_token,omitempty"`
			ExpiresIn    uint   `json:"expires_in,omitempty" cbor:"expires_in,omitempty"`
			OpenID       string `json:"openid,omitempty" cbor:"openid,omitempty"`
			Scope        string `json:"scope,omitempty" cbor:"scope,omitempty"`
			UnionID      string `json:"unionid,omitempty" cbor:"unionid,omitempty"`
		}

		token := &wechatToken{}
		if err := util.RequestJSON(cctx, cli, "GET", uri, nil, token); err != nil {
			return nil, err
		}
		rt.Payload, _ = cbor.Marshal(token)

		type wechatUser struct {
			Sub     string `json:"unionid" cbor:"unionid"`
			Name    string `json:"nickname" cbor:"nickname"`
			Picture string `json:"headimgurl" cbor:"headimgurl"`
		}

		user := &wechatUser{}
		v = url.Values{
			"access_token": {token.AccessToken},
			"openid":       {token.OpenID},
		}
		uri = "https://api.weixin.qq.com/sns/userinfo?" + v.Encode()
		if err := util.RequestJSON(cctx, cli, "GET", uri, nil, user); err != nil {
			return nil, err
		}
		rt.Sub = user.Sub
		rt.User.Name = user.Name
		rt.User.Picture = user.Picture

	case "github":
		token, err := provider.Exchange(cctx, code)
		if err != nil {
			return nil, err
		}
		rt.Payload, _ = cbor.Marshal(token)

		type githubUser struct {
			Sub     string `json:"login" cbor:"login"`
			Name    string `json:"name" cbor:"name"`
			Picture string `json:"avatar_url" cbor:"avatar_url"`
		}

		user := &githubUser{}
		api := "https://api.github.com/user"
		cli = provider.Client(cctx, token)
		if err := util.RequestJSON(ctx, cli, "GET", api, nil, user); err != nil {
			return nil, err
		}

		rt.Sub = user.Sub
		rt.User.Name = user.Name
		rt.User.Picture = user.Picture

	case "google":
		token, err := provider.Exchange(cctx, code)
		if err != nil {
			return nil, err
		}
		rt.Payload, _ = cbor.Marshal(token)

		type googleUser struct {
			Sub     string `json:"id" cbor:"id"`
			Name    string `json:"name" cbor:"name"`
			Picture string `json:"picture" cbor:"picture"`
		}

		user := &googleUser{}
		api := "https://www.googleapis.com/oauth2/v1/userinfo"
		cli = provider.Client(cctx, token)
		if err := util.RequestJSON(ctx, cli, "GET", api, nil, user); err != nil {
			return nil, err
		}

		rt.Sub = user.Sub
		rt.User.Name = user.Name
		rt.User.Picture = user.Picture

	default:
		return nil, fmt.Errorf("unknown provider %q", idp)
	}

	return rt, nil
}

func (a *AuthN) createState(idp, client_id, next_url string) (string, error) {
	obj := &cose.Mac0Message[key.IntMap]{
		Unprotected: cose.Headers{},
		Payload: key.IntMap{
			0: idp,
			1: time.Now().Add(5 * time.Minute).Unix(),
			2: conf.Config.Rand.Uint32(),
			3: next_url,
		},
	}
	err := obj.Compute(a.stateMACer, []byte(client_id))
	if err != nil {
		return "", err
	}

	data, err := cbor.Marshal(obj)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func (a *AuthN) verifyState(idp, client_id, state string) (*url.URL, error) {
	data, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return nil, err
	}

	obj := &cose.Mac0Message[key.IntMap]{}
	if err = cbor.Unmarshal(data, obj); err != nil {
		return nil, err
	}
	if err = obj.Verify(a.stateMACer, []byte(client_id)); err != nil {
		return nil, err
	}
	if v, _ := obj.Payload.GetString(0); v != idp {
		return nil, fmt.Errorf("invalid state for provider %q", idp)
	}
	if v, _ := obj.Payload.GetInt64(1); v < time.Now().Unix() {
		return nil, fmt.Errorf("expired state")
	}

	next_url, _ := obj.Payload.GetString(3)
	return url.Parse(next_url)
}
