package api

import (
	"net/http"
	"strings"

	"github.com/mssola/useragent"
	"github.com/teambition/gear"
	"github.com/yiwen-ai/auth-api/src/bll"
	"github.com/yiwen-ai/auth-api/src/util"
)

func (a *AuthN) PassKeyGetChallenge(ctx *gear.Context) error {
	output, err := a.blls.AuthN.PassKeyGetChallenge(ctx)
	if err != nil {
		return gear.ErrInternalServerError.From(err)
	}

	return ctx.OkSend(output)
}

func (a *AuthN) PassKeyVerifyRegistration(ctx *gear.Context) error {
	input := &bll.RegistrationCredentialInput{}
	if err := ctx.ParseBody(input); err != nil {
		return err
	}
	input.IP = ctx.IP().String()
	locale := ctx.AcceptLanguage()
	if i := strings.IndexAny(locale, "-_"); i > 0 {
		locale = locale[:i]
	}
	input.Locale = locale
	input.UID = nil
	// add passkey to the logined user
	if sess := gear.CtxValue[bll.SessionOutput](ctx); sess != nil && sess.UID != nil {
		input.UID = sess.UID
	}

	output, err := a.blls.AuthN.PassKeyVerifyRegistration(ctx, input)
	if err != nil {
		return gear.ErrInternalServerError.From(err)
	}
	action := bll.LogActionSysCreateUser
	if input.UID != nil && *input.UID == *output.UID {
		action = bll.LogActionSysUpdateUser
	}

	a.blls.Logbase.Log(ctx, action, 1, *output.UID, *output.UID, &bll.LogPayload{
		Idp: util.Ptr("pk"),
		Sub: util.Ptr(input.ID),
	})
	output.UID = nil

	return ctx.OkSend(output)
}

func (a *AuthN) PassKeyVerifyAuthentication(ctx *gear.Context) error {
	input := &bll.AuthenticationCredentialInput{}
	if err := ctx.ParseBody(input); err != nil {
		return err
	}
	input.IP = ctx.IP().String()
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

	output, err := a.blls.AuthN.PassKeyVerifyAuthentication(ctx, input)
	if err != nil {
		return gear.ErrInternalServerError.From(err)
	}

	a.blls.Logbase.Log(ctx, bll.LogActionUserLogin, 1, *output.UID, *output.UID, &bll.LogPayload{
		Idp: util.Ptr("pk"),
		Sub: util.Ptr(input.ID),
	})

	domain := a.cookie.Domain
	didCookie := &http.Cookie{
		Name:     didCookieName,
		Value:    output.SID.String(),
		HttpOnly: true,
		Secure:   a.cookie.Secure,
		MaxAge:   3600 * 24 * 366,
		Path:     "/",
		Domain:   domain,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(ctx.Res, didCookie)

	sessCookie := &http.Cookie{
		Name:     a.cookie.NamePrefix + "_SESS",
		Value:    output.Session,
		HttpOnly: true,
		Secure:   a.cookie.Secure,
		MaxAge:   int(a.cookie.ExpiresIn),
		Path:     "/",
		Domain:   domain,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(ctx.Res, sessCookie)
	output.UID = nil
	return ctx.OkSend(output)
}
