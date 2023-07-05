package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
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
	"github.com/yiwen-ai/auth-api/src/util"
)

type AuthN struct {
	blls       *bll.Blls
	providers  map[string]*oauth2.Config
	stateMACer key.MACer
	cookie     conf.Cookie
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
	provider, ok := a.providers[idp]
	if !ok {
		return gear.ErrBadRequest.WithMsgf("unknown provider %q", idp)
	}

	state, err := a.createState(idp, provider.ClientID)
	if err != nil {
		return gear.ErrInternalServerError.WithMsgf("failed to create state: %v", err)
	}

	url := provider.AuthCodeURL(state)
	return ctx.Redirect(url)
}

// Get ..
func (a *AuthN) Callback(ctx *gear.Context) error {
	idp := ctx.Param("idp")
	provider, ok := a.providers[idp]
	if !ok {
		return gear.ErrBadRequest.WithMsgf("unknown provider %q", idp)
	}

	code := ctx.Query("code")
	state := ctx.Query("state")
	if err := a.verifyState(idp, provider.ClientID, state); err != nil {
		return gear.ErrBadRequest.WithMsgf("invalid state: %v", err)
	}

	cctx := context.WithValue(ctx, oauth2.HTTPClient, util.ExternalHTTPClient)
	token, err := provider.Exchange(cctx, code)
	if err != nil {
		return gear.ErrInternalServerError.WithMsgf("get token failed: %v", err)
	}

	client := provider.Client(cctx, token)
	var input *bll.AuthNInput
	switch idp {
	case "github":
		input, err = a.blls.AuthN.GithubUser(cctx, client)
		if err != nil {
			return gear.ErrInternalServerError.From(err)
		}
	default:
		return gear.ErrInternalServerError.WithMsgf("unknown provider %q", idp)
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
		return gear.ErrInternalServerError.From(err)
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

	return ctx.OkHTML("Login success!")
}

func (a *AuthN) createState(idp, client_id string) (string, error) {
	obj := &cose.Mac0Message[key.IntMap]{
		Unprotected: cose.Headers{},
		Payload: key.IntMap{
			0: idp,
			1: time.Now().Add(5 * time.Minute).Unix(),
			2: conf.Config.Rand.Uint32(),
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

func (a *AuthN) verifyState(idp, client_id, state string) error {
	data, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return err
	}

	obj := &cose.Mac0Message[key.IntMap]{}
	if err = cbor.Unmarshal(data, obj); err != nil {
		return err
	}
	if err = obj.Verify(a.stateMACer, []byte(client_id)); err != nil {
		return err
	}
	if v, _ := obj.Payload.GetString(0); v != idp {
		return fmt.Errorf("invalid state for provider %q", idp)
	}
	if v, _ := obj.Payload.GetInt64(1); v < time.Now().Unix() {
		return fmt.Errorf("expired state")
	}

	return nil
}
