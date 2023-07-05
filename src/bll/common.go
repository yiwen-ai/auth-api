package bll

import (
	"context"

	"github.com/yiwen-ai/auth-api/src/service"
	"github.com/yiwen-ai/auth-api/src/util"
)

func init() {
	util.DigProvide(NewBlls)
}

// Blls ...
type Blls struct {
	svc *service.Userbase

	AuthN   *AuthN
	Session *Session
}

// NewBlls ...
func NewBlls(svc *service.Userbase, oss *service.OSS) *Blls {
	return &Blls{
		svc:     svc,
		AuthN:   &AuthN{svc, oss},
		Session: &Session{svc},
	}
}

func (b *Blls) Stats(ctx context.Context) (res map[string]any, err error) {
	return b.svc.Stats(ctx)
}

type SuccessResponse[T any] struct {
	Result T `json:"result" cbor:"result"`
}

type UpdateUserInput struct {
	ID        util.ID `json:"id" cbor:"id"`
	UpdatedAt int64   `json:"updated_at" cbor:"updated_at"`
	Picture   string  `json:"picture,omitempty" cbor:"picture,omitempty"`
}

type UserInfo struct {
	CN      string `json:"cn" cbor:"cn"`
	Name    string `json:"name" cbor:"name"`
	Locale  string `json:"locale" cbor:"locale"`
	Picture string `json:"picture" cbor:"picture"`
	Status  int8   `json:"status" cbor:"status"`
}

type AuthNInput struct {
	Idp        string   `json:"idp" cbor:"idp"`
	Aud        string   `json:"aud" cbor:"aud"`
	Sub        string   `json:"sub" cbor:"sub"`
	ExpiresIn  uint     `json:"expires_in" cbor:"expires_in"`
	Scope      []string `json:"scope" cbor:"scope"`
	Ip         string   `json:"ip" cbor:"ip"`
	DeviceID   string   `json:"device_id" cbor:"device_id"`
	DeviceDesc string   `json:"device_desc" cbor:"device_desc"`
	Payload    []byte   `json:"payload" cbor:"payload"`
	User       UserInfo `json:"user" cbor:"user"`
}

type AuthNSessionOutput struct {
	SID           util.ID   `json:"sid" cbor:"sid"`
	UID           util.ID   `json:"uid" cbor:"uid"`
	Sub           util.UUID `json:"sub" cbor:"sub"`
	Session       string    `json:"session" cbor:"session"`
	UserCreatedAt int64     `json:"user_created_at" cbor:"user_created_at"`
}

type AuthNOutput struct {
	Idp string  `json:"idp" cbor:"idp"`
	Aud string  `json:"aud" cbor:"aud"`
	Sub string  `json:"sub" cbor:"sub"`
	UID util.ID `json:"uid" cbor:"uid"`
}

type SessionInput struct {
	Session   string   `json:"session" cbor:"session"`
	Aud       *util.ID `json:"aud" cbor:"aud"`
	ExpiresIn uint     `json:"expires_in" cbor:"expires_in"`
}

type SessionOutput struct {
	Sub         *util.UUID `json:"sub,omitempty" cbor:"sub,omitempty"`
	UID         *util.ID   `json:"uid,omitempty" cbor:"uid,omitempty"`
	AccessToken string     `json:"access_token,omitempty" cbor:"access_token,omitempty"`
	IDToken     string     `json:"id_token,omitempty" cbor:"id_token,omitempty"`
	ExpiresIn   uint       `json:"expires_in,omitempty" cbor:"expires_in,omitempty"`
}
