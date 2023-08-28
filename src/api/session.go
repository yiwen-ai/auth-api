package api

import (
	"net/http"

	_ "github.com/ldclabs/cose/key/hmac"
	"github.com/teambition/gear"

	"github.com/yiwen-ai/auth-api/src/bll"
	"github.com/yiwen-ai/auth-api/src/conf"
	"github.com/yiwen-ai/auth-api/src/util"
)

type Session struct {
	blls   *bll.Blls
	cookie conf.Cookie
}

func NewSession(blls *bll.Blls, cfg *conf.ConfigTpl) *Session {
	sess := &Session{
		blls:   blls,
		cookie: cfg.Cookie,
	}

	return sess
}

func (a *Session) Verify(ctx *gear.Context) error {
	sess := a.extractSession(ctx)
	if sess == "" {
		return gear.ErrUnauthorized.WithMsg("missing session")
	}

	output, err := a.blls.Session.Verify(ctx, &bll.SessionInput{
		Session:   sess,
		Aud:       &util.JARVIS,
		ExpiresIn: 3600,
	})
	if err != nil {
		return gear.ErrUnauthorized.From(err)
	}

	if output.UID == nil {
		return gear.ErrInternalServerError.WithMsg("missing uid")
	}

	header := gear.CtxValue[util.ContextHTTPHeader](ctx)
	http.Header(*header).Set("x-auth-user", output.UID.String())
	ctx.WithContext(gear.CtxWith[bll.SessionOutput](ctx.Context(), output))
	return nil
}

func (a *Session) AccessToken(ctx *gear.Context) error {
	sess := a.extractSession(ctx)
	if sess == "" {
		return gear.ErrUnauthorized.WithMsg("missing session")
	}

	output, err := a.blls.Session.AccessToken(ctx, &bll.SessionInput{
		Session:   sess,
		Aud:       &util.JARVIS,
		ExpiresIn: 3600,
	})
	if err != nil {
		return gear.ErrUnauthorized.From(err)
	}

	output.SID = nil // should not return sid
	output.UID = nil // should not return uid
	return ctx.OkSend(output)
}

func (a *Session) UserInfo(ctx *gear.Context) error {
	sess := gear.CtxValue[bll.SessionOutput](ctx)
	if sess == nil {
		return gear.ErrUnauthorized.WithMsg("missing session")
	}
	output, err := a.blls.Session.UserInfo(ctx, sess.UID, "")
	if err != nil {
		return gear.ErrInternalServerError.From(err)
	}
	output.ID = nil // should not return id

	return ctx.OkSend(output)
}

func (a *Session) Logout(ctx *gear.Context) error {
	sess := gear.CtxValue[bll.SessionOutput](ctx)
	if sess == nil || sess.SID == nil {
		return gear.ErrUnauthorized.WithMsg("missing session")
	}

	output, err := a.blls.Session.Delete(ctx, *sess.SID)
	if err != nil {
		return gear.ErrInternalServerError.From(err)
	}

	go a.blls.Logbase.Log(ctx, bll.LogActionUserLogout, 1, *sess.UID, *sess.UID, nil)

	didCookie := &http.Cookie{
		Name:     a.cookie.NamePrefix + "_DID",
		Value:    "",
		HttpOnly: true,
		Secure:   a.cookie.Secure,
		MaxAge:   -1,
		Path:     "/",
		Domain:   a.cookie.Domain,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(ctx.Res, didCookie)

	sessCookie := &http.Cookie{
		Name:     a.cookie.NamePrefix + "_SESS",
		Value:    "",
		HttpOnly: true,
		Secure:   a.cookie.Secure,
		MaxAge:   -1,
		Path:     "/",
		Domain:   a.cookie.Domain,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(ctx.Res, sessCookie)
	return ctx.OkSend(output)
}

func (a *Session) extractSession(ctx *gear.Context) string {
	sess := ctx.GetHeader("X-Session")
	if sess == "" {
		if cookie, _ := ctx.Req.Cookie(a.cookie.NamePrefix + "_SESS"); cookie != nil {
			sess = cookie.Value
		}
	}
	return sess
}
