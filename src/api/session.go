package api

import (
	_ "github.com/ldclabs/cose/key/hmac"
	"github.com/teambition/gear"

	"github.com/yiwen-ai/auth-api/src/bll"
	"github.com/yiwen-ai/auth-api/src/conf"
	"github.com/yiwen-ai/auth-api/src/util"
)

type Session struct {
	blls       *bll.Blls
	cookieName string
}

func NewSession(blls *bll.Blls, cfg *conf.ConfigTpl) *Session {
	sess := &Session{
		blls:       blls,
		cookieName: cfg.Cookie.NamePrefix + "_SESS",
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
	output.UID = nil // should not return uid

	return ctx.OkSend(output)
}

func (a *Session) UserInfo(ctx *gear.Context) error {
	sess := gear.CtxValue[bll.SessionOutput](ctx)
	if sess == nil {
		return gear.ErrUnauthorized.WithMsg("missing session")
	}
	output, err := a.blls.Session.UserInfo(ctx, *sess.UID)
	if err != nil {
		return gear.ErrInternalServerError.From(err)
	}

	return ctx.OkSend(output)
}

func (a *Session) extractSession(ctx *gear.Context) string {
	sess := ctx.GetHeader("X-Session")
	if sess == "" {
		if cookie, _ := ctx.Req.Cookie(a.cookieName); cookie != nil {
			sess = cookie.Value
		}
	}
	return sess
}
