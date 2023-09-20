package bll

import (
	"context"

	"github.com/yiwen-ai/auth-api/src/conf"
	"github.com/yiwen-ai/auth-api/src/service"
	"github.com/yiwen-ai/auth-api/src/util"
)

func init() {
	util.DigProvide(NewBlls)
}

// Blls ...
type Blls struct {
	AuthN      *AuthN
	Logbase    *Logbase
	Session    *Session
	Walletbase *Walletbase
}

// NewBlls ...
func NewBlls(oss *service.OSS) *Blls {
	cfg := conf.Config.Base
	return &Blls{
		AuthN:      &AuthN{svc: service.APIHost(cfg.Userbase), oss: oss},
		Logbase:    &Logbase{svc: service.APIHost(cfg.Logbase)},
		Session:    &Session{svc: service.APIHost(cfg.Userbase)},
		Walletbase: &Walletbase{svc: service.APIHost(cfg.Walletbase)},
	}
}

func (b *Blls) Stats(ctx context.Context) (res map[string]any, err error) {
	return b.Session.svc.Stats(ctx)
}

type SuccessResponse[T any] struct {
	Result T `json:"result" cbor:"result"`
}

type UpdateUserInput struct {
	ID      util.ID `json:"id" cbor:"id"`
	Picture string  `json:"picture,omitempty" cbor:"picture,omitempty"`
}

type UserInfo struct {
	ID      *util.ID `json:"id,omitempty" cbor:"id,omitempty"` // should not return to client
	CN      string   `json:"cn" cbor:"cn"`
	Name    string   `json:"name" cbor:"name"`
	Locale  string   `json:"locale" cbor:"locale"`
	Picture string   `json:"picture" cbor:"picture"`
	Status  int8     `json:"status" cbor:"status"`
}

type AuthNPK struct {
	Idp string `json:"idp" cbor:"idp"`
	Aud string `json:"aud" cbor:"aud"`
	Sub string `json:"sub" cbor:"sub"`
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
	CoAuthN    *AuthNPK `json:"co_authn,omitempty" cbor:"co_authn,omitempty"`
}

type AuthNSessionOutput struct {
	SID           util.ID   `json:"sid" cbor:"sid"`
	UID           util.ID   `json:"uid" cbor:"uid"`
	Sub           util.UUID `json:"sub" cbor:"sub"`
	Session       string    `json:"session" cbor:"session"`
	Picture       string    `json:"picture" cbor:"picture"`
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
	SID         *util.ID   `json:"sid,omitempty" cbor:"sid,omitempty"`
	Sub         *util.UUID `json:"sub,omitempty" cbor:"sub,omitempty"`
	UID         *util.ID   `json:"uid,omitempty" cbor:"uid,omitempty"`
	AccessToken string     `json:"access_token,omitempty" cbor:"access_token,omitempty"`
	IDToken     string     `json:"id_token,omitempty" cbor:"id_token,omitempty"`
	ExpiresIn   uint       `json:"expires_in,omitempty" cbor:"expires_in,omitempty"`
}
