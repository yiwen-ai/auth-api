package api

import (
	"fmt"
	"strings"

	"github.com/teambition/gear"

	"github.com/yiwen-ai/auth-api/src/bll"
	"github.com/yiwen-ai/auth-api/src/conf"
	"github.com/yiwen-ai/auth-api/src/util"
)

func init() {
	util.DigProvide(newAPIs)
	util.DigProvide(newRouters)
}

// APIs ..
type APIs struct {
	Healthz *Healthz
	AuthN   *AuthN
	Session *Session
}

func newAPIs(blls *bll.Blls) *APIs {
	return &APIs{
		Healthz: &Healthz{blls: blls},
		AuthN:   NewAuth(blls, &conf.Config),
		Session: NewSession(blls, &conf.Config),
	}
}

func todo(ctx *gear.Context) error {
	return gear.ErrNotFound
}

func newRouters(apis *APIs) []*gear.Router {

	router := gear.NewRouter()
	// health check
	router.Get("/healthz", apis.Healthz.Get)
	router.Get("/access_token", apis.Session.AccessToken)
	router.Get("/userinfo", apis.Session.Verify, apis.Session.UserInfo)

	router.Get("/idp/:idp/authorize", apis.AuthN.Login)
	router.Get("/idp/:idp/callback", apis.AuthN.Callback)
	router.Get("/oauth2/authorize", todo)
	router.Get("/oauth2/access_token", todo)
	router.Otherwise(func(ctx *gear.Context) error {
		if !strings.Contains(conf.Config.Home, ctx.Req.Host) {
			return ctx.Redirect(conf.Config.Home)
		}
		return ctx.HTML(404, fmt.Sprintf("%q not found", ctx.Req.URL.String()))
	})

	return []*gear.Router{router}
}
