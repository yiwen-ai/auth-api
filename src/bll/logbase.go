package bll

import (
	"context"
	"net/url"

	"github.com/fxamacker/cbor/v2"
	"github.com/teambition/gear"
	"github.com/yiwen-ai/auth-api/src/service"
	"github.com/yiwen-ai/auth-api/src/util"
)

const (
	LogActionSysCreateUser     = "sys.create.user"
	LogActionSysUpdateUser     = "sys.update.user"
	LogActionSysUpdateGroup    = "sys.update.group"
	LogActionSysUpdateCreation = "sys.update.creation"
	LogActionUserLogin         = "user.login"
	LogActionUserAuthz         = "user.authz"
	LogActionUserUpdate        = "user.update"
	LogActionUserUpdateCN      = "user.update.cn"
	LogActionUserLogout        = "user.logout"
	LogActionUserCollect       = "user.collect"
	LogActionUserFollow        = "user.follow"
	LogActionUserSubscribe     = "user.subscribe"
	LogActionUserSponsor       = "user.sponsor"
	LogActionGroupCreate       = "group.create"
	LogActionGroupUpdate       = "group.update"
	LogActionGroupUpdateCN     = "group.update.cn"
	LogActionGroupTransfer     = "group.transfer"
	LogActionGroupDelete       = "group.delete"
	LogActionGroupCreateUser   = "group.create.user"
	LogActionGroupUpdateUser   = "group.update.user"
	LogActionGroupAddMember    = "group.add.member"
	LogActionGroupUpdateMember = "group.update.member"
	LogActionGroupRemoveMember = "group.remove.member"
)

type Logbase struct {
	svc service.APIHost
}

type LogOutput struct {
	UID     util.ID     `json:"uid" cbor:"uid"`
	ID      util.ID     `json:"id" cbor:"id"`
	Status  int8        `json:"status" cbor:"status"`
	Action  string      `json:"action" cbor:"action"`
	GID     *util.ID    `json:"gid,omitempty" cbor:"gid,omitempty"`
	IP      *string     `json:"ip,omitempty" cbor:"ip,omitempty"`
	Payload *util.Bytes `json:"payload,omitempty" cbor:"payload,omitempty"`
	Tokens  *uint32     `json:"tokens,omitempty" cbor:"tokens,omitempty"`
	Error   *string     `json:"error,omitempty" cbor:"error,omitempty"`
}

func (b *Logbase) Get(ctx context.Context, uid, id util.ID, fields string) (*LogOutput, error) {
	output := SuccessResponse[LogOutput]{}

	query := url.Values{}
	query.Add("uid", uid.String())
	query.Add("id", id.String())
	if fields != "" {
		query.Add("fields", fields)
	}
	// ignore error
	if err := b.svc.Get(ctx, "/v1/log?"+query.Encode(), &output); err != nil {
		return nil, err
	}

	return &output.Result, nil
}

type CreateLogInput struct {
	UID     util.ID    `json:"uid" cbor:"uid"`
	GID     util.ID    `json:"gid" cbor:"gid"`
	Action  string     `json:"action" cbor:"action"`
	Status  int8       `json:"status" cbor:"status"`
	IP      string     `json:"ip" cbor:"ip"`
	Payload util.Bytes `json:"payload" cbor:"payload"`
	Tokens  uint32     `json:"tokens" cbor:"tokens"`
}

type LogPayload struct {
	Idp *string `json:"idp,omitempty" cbor:"idp,omitempty"`
	Sub *string `json:"sub,omitempty" cbor:"sub,omitempty"`
}

func (b *Logbase) Log(ctx *gear.Context, action string, status int8, uid, gid util.ID, payload any) (*LogOutput, error) {
	input := CreateLogInput{
		UID:     uid,
		GID:     gid,
		Action:  action,
		Status:  status,
		Payload: util.Bytes{0xa0}, // {}
		IP:      ctx.IP().String(),
	}

	if payload != nil {
		data, err := cbor.Marshal(payload)
		if err != nil {
			return nil, err
		}
		input.Payload = data
	}

	output := SuccessResponse[LogOutput]{}
	if err := b.svc.Post(ctx, "/v1/log", input, &output); err != nil {
		return nil, err
	}

	return &output.Result, nil
}

type UpdateLog struct {
	UID     util.ID     `json:"uid" cbor:"uid"`
	ID      util.ID     `json:"id" cbor:"id"`
	Status  int8        `json:"status" cbor:"status"`
	Payload *util.Bytes `json:"payload,omitempty" cbor:"payload,omitempty"`
	Tokens  *uint32     `json:"tokens,omitempty" cbor:"tokens,omitempty"`
	Error   *string     `json:"error,omitempty" cbor:"error,omitempty"`
}

func (b *Logbase) Update(ctx context.Context, input *UpdateLog) (*LogOutput, error) {
	output := SuccessResponse[LogOutput]{}

	if err := b.svc.Patch(ctx, "/v1/log", input, &output); err != nil {
		return nil, err
	}

	return &output.Result, nil
}
