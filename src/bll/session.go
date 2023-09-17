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

type UpdateSpecialFieldInput struct {
	ID        util.ID `json:"id" cbor:"id"`
	UpdatedAt int64   `json:"updated_at" cbor:"updated_at"`
	Status    *int8   `json:"status,omitempty" cbor:"status,omitempty"`
	Rating    *int8   `json:"rating,omitempty" cbor:"rating,omitempty"`
	Kind      *int8   `json:"kind,omitempty" cbor:"kind,omitempty"`
	Email     *string `json:"email,omitempty" cbor:"email,omitempty"`
	Phone     *string `json:"phone,omitempty" cbor:"phone,omitempty"`
}

type userInfo struct {
	ID        util.ID `json:"id" cbor:"id"`
	UpdatedAt int64   `json:"updated_at" cbor:"updated_at"`
	Status    int8    `json:"status" cbor:"status"`
}

func (b *Session) DisabledUser(ctx context.Context, uid util.ID) (*SuccessResponse[userInfo], error) {
	res := SuccessResponse[userInfo]{}
	api := "/v1/user?fields=cn,name,updated_at,status&id=" + uid.String()
	if err := b.svc.Get(ctx, api, &res); err != nil {
		return nil, err
	}

	if res.Result.Status == -2 {
		return &res, nil
	}

	if res.Result.Status >= 0 {
		updatedAt := res.Result.UpdatedAt
		res = SuccessResponse[userInfo]{}
		if err := b.svc.Patch(ctx, "/v1/sys/user/update_status", &UpdateSpecialFieldInput{
			ID:        uid,
			UpdatedAt: updatedAt,
			Status:    util.Ptr(int8(-1)),
		}, &res); err != nil {
			return nil, err
		}
	}

	updatedAt := res.Result.UpdatedAt
	res = SuccessResponse[userInfo]{}
	if err := b.svc.Patch(ctx, "/v1/sys/user/update_status", &UpdateSpecialFieldInput{
		ID:        uid,
		UpdatedAt: updatedAt,
		Status:    util.Ptr(int8(-2)),
	}, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
