package bll

import (
	"context"

	"github.com/yiwen-ai/auth-api/src/service"
	"github.com/yiwen-ai/auth-api/src/util"
)

type Session struct {
	svc *service.Userbase
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

func (b *Session) UserInfo(ctx context.Context, uid util.ID) (*UserInfo, error) {
	output := SuccessResponse[UserInfo]{}
	if err := b.svc.Get(ctx, "/v1/user?fields=cn,name,locale,picture,status&id="+uid.String(), &output); err != nil {
		return nil, err
	}
	return &output.Result, nil
}
