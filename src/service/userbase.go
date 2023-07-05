package service

import (
	"context"
	"net/http"

	"github.com/yiwen-ai/auth-api/src/conf"
	"github.com/yiwen-ai/auth-api/src/util"
)

func init() {
	util.DigProvide(NewUserbase)
}

type Userbase struct {
	host string
	cli  *http.Client
}

func NewUserbase() *Userbase {
	return &Userbase{
		host: conf.Config.Userbase.Host,
		cli:  util.HTTPClient,
	}
}

func (s *Userbase) Stats(ctx context.Context) (map[string]any, error) {
	res := make(map[string]any)
	err := s.Get(ctx, "/healthz", &res)
	return res, err
}

func (s *Userbase) Get(ctx context.Context, api string, output any) error {
	return util.RequestCBOR(ctx, s.cli, http.MethodGet, s.host+api, nil, output)
}

func (s *Userbase) Delete(ctx context.Context, api string, output any) error {
	return util.RequestCBOR(ctx, s.cli, http.MethodDelete, s.host+api, nil, output)
}

func (s *Userbase) Post(ctx context.Context, api string, input, output any) error {
	return util.RequestCBOR(ctx, s.cli, http.MethodPost, s.host+api, input, output)
}

func (s *Userbase) Patch(ctx context.Context, api string, input, output any) error {
	return util.RequestCBOR(ctx, s.cli, http.MethodPatch, s.host+api, input, output)
}
