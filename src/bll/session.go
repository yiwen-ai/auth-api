package bll

import (
	"context"

	"github.com/yiwen-ai/auth-api/src/service"
	"github.com/yiwen-ai/auth-api/src/util"
)

type Session struct {
	svc service.APIHost
}

func (b *Session) Verify(ctx context.Context, input *SessionInput) (*SessionOutput, error) {
	output := SuccessResponse[SessionOutput]{}
	if err := b.svc.Post(ctx, "/v1/session/verify", input, &output); err != nil {
		return nil, err
	}
	return &output.Result, nil
}

func (b *Session) AccessToken(ctx context.Context, input *SessionInput) (*SessionOutput, error) {
	output := SuccessResponse[SessionOutput]{}
	if err := b.svc.Post(ctx, "/v1/session/renew_token", input, &output); err != nil {
		return nil, err
	}
	return &output.Result, nil
}

func (b *Session) UserInfo(ctx context.Context, id *util.ID, cn string) (*UserInfo, error) {
	output := SuccessResponse[UserInfo]{}
	api := "/v1/user?fields=cn,name,locale,picture,status"
	if id != nil {
		api += "&id=" + id.String()
	} else {
		api += "&cn=" + cn
	}

	if err := b.svc.Get(ctx, api, &output); err != nil {
		return nil, err
	}
	return &output.Result, nil
}

func (b *Session) Delete(ctx context.Context, sid util.ID) (*SuccessResponse[bool], error) {
	output := SuccessResponse[bool]{}
	if err := b.svc.Delete(ctx, "/v1/session?sid="+sid.String(), &output); err != nil {
		return nil, err
	}
	return &output, nil
}
