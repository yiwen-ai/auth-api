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
		default:
			panic(fmt.Sprintf("unknown provider %q\n", k))
		}

		authn.providers[k] = &oauth2.Config{
			ClientID:     v.ClientID,
			ClientSecret: v.ClientSecret,
			Scopes:       v.Scopes,
			RedirectURL:  "",
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

	url := provider.AuthCodeURL(state)
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

	cctx := context.WithValue(ctx, oauth2.HTTPClient, util.ExternalHTTPClient)
	token, err := provider.Exchange(cctx, code)
	if err != nil {
		next := a.authURL.GenNextUrl(nextURL, 403, xid)
		logging.SetTo(ctx, "error", fmt.Sprintf("get token failed: %v", err))
		return ctx.Redirect(next)
	}

	client := provider.Client(cctx, token)
	var input *bll.AuthNInput
	switch idp {
	case "github":
		input, err = a.blls.AuthN.GithubUser(cctx, client)
		if err != nil {
			next := a.authURL.GenNextUrl(nextURL, 500, xid)
			logging.SetTo(ctx, "error", fmt.Sprintf("AuthN.GithubUser failed: %v", err))
			return ctx.Redirect(next)
		}
	default:
		next := a.authURL.GenNextUrl(nextURL, 403, xid)
		logging.SetTo(ctx, "error", fmt.Sprintf("unknown provider %q", idp))
		return ctx.Redirect(next)
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
	input.Payload, _ = cbor.Marshal(token)
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

	res, err := a.blls.AuthN.LoginOrNew(cctx, input)
	if err != nil {
		next := a.authURL.GenNextUrl(nextURL, 500, xid)
		logging.SetTo(ctx, "error", fmt.Sprintf("AuthN.LoginOrNew failed: %v", err))
		return ctx.Redirect(next)
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
