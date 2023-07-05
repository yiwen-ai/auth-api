package api

import (
	"github.com/teambition/gear"

	"github.com/yiwen-ai/auth-api/src/bll"
	"github.com/yiwen-ai/auth-api/src/conf"
	"github.com/yiwen-ai/auth-api/src/logging"
)

// Healthz ..
type Healthz struct {
	blls *bll.Blls
}

// Get ..
func (a *Healthz) Get(ctx *gear.Context) error {
	stats, err := a.blls.Stats(ctx)
	if err != nil {
		return gear.ErrInternalServerError.From(err)
	}

	logging.SetTo(ctx, "stats", stats)
	return ctx.OkJSON(bll.SuccessResponse[map[string]string]{Result: GetVersion()})
}

func GetVersion() map[string]string {
	return map[string]string{
		"name":      conf.AppName,
		"version":   conf.AppVersion,
		"buildTime": conf.BuildTime,
		"gitSHA1":   conf.GitSHA1,
	}
}
