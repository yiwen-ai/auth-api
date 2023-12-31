package bll

import (
	"context"

	"github.com/yiwen-ai/auth-api/src/util"
)

type ChallengeOutput struct {
	RpID       string     `json:"rp_id" cbor:"rp_id"`
	RpName     string     `json:"rp_name" cbor:"rp_name"`
	UserHandle string     `json:"user_handle" cbor:"user_handle"`
	Challenge  util.Bytes `json:"challenge" cbor:"challenge"`
}

type RegistrationCredentialInput struct {
	ID                string     `json:"id" cbor:"id"`
	DisplayName       string     `json:"display_name" cbor:"display_name"`
	AuthenticatorData util.Bytes `json:"authenticator_data" cbor:"authenticator_data"`
	ClientData        util.Bytes `json:"client_data" cbor:"client_data"`
	IP                string     `json:"ip" cbor:"ip"`
	Locale            string     `json:"locale" cbor:"locale"`
	UID               *util.ID   `json:"uid,omitempty" cbor:"uid,omitempty"`
}

func (i *RegistrationCredentialInput) Validate() error {
	// will be validated on userbase
	return nil
}

type AuthenticationCredentialInput struct {
	ID                string     `json:"id" cbor:"id"`
	AuthenticatorData util.Bytes `json:"authenticator_data" cbor:"authenticator_data"`
	ClientData        util.Bytes `json:"client_data" cbor:"client_data"`
	Signature         util.Bytes `json:"signature" cbor:"signature"`
	IP                string     `json:"ip" cbor:"ip"`
	DeviceID          string     `json:"device_id" cbor:"device_id"`
	DeviceDesc        string     `json:"device_desc" cbor:"device_desc"`
}

func (i *AuthenticationCredentialInput) Validate() error {
	// will be validated on userbase
	return nil
}

func (b *AuthN) PassKeyGetChallenge(ctx context.Context) (*ChallengeOutput, error) {
	output := SuccessResponse[ChallengeOutput]{}
	if err := b.svc.Get(ctx, "/v1/passkey/get_challenge", &output); err != nil {
		return nil, err
	}

	return &output.Result, nil
}

func (b *AuthN) PassKeyVerifyRegistration(ctx context.Context, input *RegistrationCredentialInput) (*AuthNOutput, error) {
	output := SuccessResponse[AuthNOutput]{}
	if err := b.svc.Post(ctx, "/v1/passkey/verify_registration", input, &output); err != nil {
		return nil, err
	}

	return &output.Result, nil
}

func (b *AuthN) PassKeyVerifyAuthentication(ctx context.Context, input *AuthenticationCredentialInput) (*AuthNSessionOutput, error) {
	output := SuccessResponse[AuthNSessionOutput]{}
	if err := b.svc.Post(ctx, "/v1/passkey/verify_authentication", input, &output); err != nil {
		return nil, err
	}

	return &output.Result, nil
}
