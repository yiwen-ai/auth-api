package service

import (
	"context"
	"net/http"

	"github.com/yiwen-ai/auth-api/src/util"
)

type APIHost string

func (h APIHost) Stats(ctx context.Context) (map[string]any, error) {
	res := make(map[string]any)
	err := h.Get(ctx, "/healthz", &res)
	return res, err
}

func (h APIHost) Get(ctx context.Context, api string, output any) error {
	return util.RequestCBOR(ctx, util.HTTPClient, http.MethodGet, string(h)+api, nil, output)
}

func (h APIHost) Delete(ctx context.Context, api string, output any) error {
	return util.RequestCBOR(ctx, util.HTTPClient, http.MethodDelete, string(h)+api, nil, output)
}

func (h APIHost) Post(ctx context.Context, api string, input, output any) error {
	return util.RequestCBOR(ctx, util.HTTPClient, http.MethodPost, string(h)+api, input, output)
}

func (h APIHost) Put(ctx context.Context, api string, input, output any) error {
	return util.RequestCBOR(ctx, util.HTTPClient, http.MethodPut, string(h)+api, input, output)
}

func (h APIHost) Patch(ctx context.Context, api string, input, output any) error {
	return util.RequestCBOR(ctx, util.HTTPClient, http.MethodPatch, string(h)+api, input, output)
}
