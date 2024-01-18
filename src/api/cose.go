package api

import (
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/cose"
	"github.com/ldclabs/cose/key"
	"github.com/ldclabs/cose/key/ed25519"
	"github.com/teambition/gear"

	"github.com/yiwen-ai/auth-api/src/bll"
	"github.com/yiwen-ai/auth-api/src/util"
)

const DEFAULT_PATH = "m/123456789'/0'/0'/1/0"

type RenewKEKInput struct {
	State *util.Bytes `json:"state" cbor:"state"`
	Sig   *util.Bytes `json:"sig" cbor:"sig"`
}

func (i *RenewKEKInput) Validate() error {
	if i.State != nil || i.Sig != nil {
		if i.State == nil || i.Sig == nil {
			return gear.ErrBadRequest.WithMsg("missing state or sig")
		}
	}
	return nil
}

type RenewKEKOutput struct {
	Key       key.Key     `json:"key" cbor:"key"` // private key
	State     util.Bytes  `json:"state" cbor:"state"`
	KeyStale  bool        `json:"key_stale" cbor:"key_stale"`
	NextKey   *key.Key    `json:"next_key" cbor:"next_key"` // private key
	NextState *util.Bytes `json:"next_state" cbor:"next_state"`
}

func (a *AuthN) COSERenewKEK(ctx *gear.Context) error {
	sess := gear.CtxValue[bll.SessionOutput](ctx)
	if sess == nil || sess.UID == nil {
		return gear.ErrUnauthorized.WithMsg("missing session")
	}
	input := &RenewKEKInput{}
	if err := ctx.ParseBody(input); err != nil {
		return err
	}

	output := &RenewKEKOutput{}
	if input.State != nil {
		output.State = *input.State

		issAt, path, err := a.verifyKEKState(*input.State, *sess.UID)
		if err != nil {
			return gear.ErrBadRequest.From(err)
		}

		output.KeyStale = time.Now().Unix()-issAt > 3600*24*3

		res, err := a.blls.Session.DeriveUserKey(ctx, *sess.UID, path)
		if err != nil {
			return gear.ErrInternalServerError.From(err)
		}

		if err := cbor.Unmarshal(res, &output.Key); err != nil {
			return gear.ErrInternalServerError.From(err)
		}

		verifier, err := ed25519.NewVerifier(output.Key)
		if err != nil {
			return gear.ErrBadRequest.From(err)
		}
		if err := verifier.Verify(*input.State, *input.Sig); err != nil {
			return gear.ErrBadRequest.From(err)
		}

		if output.KeyStale {
			path, err = util.NextDerivePath(path)
			if err != nil {
				return gear.ErrBadRequest.From(err)
			}

			res, err = a.blls.Session.DeriveUserKey(ctx, *sess.UID, path)
			if err != nil {
				return gear.ErrInternalServerError.From(err)
			}

			var nextKey key.Key
			if err := cbor.Unmarshal(res, &nextKey); err != nil {
				return gear.ErrInternalServerError.From(err)
			}

			nextState, err := a.createKEKState(*sess.UID, path)
			if err != nil {
				return gear.ErrInternalServerError.From(err)
			}

			output.NextKey = &nextKey
			output.NextState = &nextState
		}

	} else {
		res, err := a.blls.Session.DeriveUserKey(ctx, *sess.UID, DEFAULT_PATH)
		if err != nil {
			return gear.ErrInternalServerError.From(err)
		}
		if err := cbor.Unmarshal(res, &output.Key); err != nil {
			return gear.ErrInternalServerError.From(err)
		}

		output.State, err = a.createKEKState(*sess.UID, DEFAULT_PATH)
		if err != nil {
			return gear.ErrInternalServerError.From(err)
		}
	}

	return ctx.OkSend(output)
}

func (a *AuthN) createKEKState(uid util.ID, path string) (util.Bytes, error) {
	obj := &cose.Mac0Message[key.IntMap]{
		Unprotected: cose.Headers{},
		Payload: key.IntMap{
			0: time.Now().Unix(),
			1: uid,
			2: path,
		},
	}
	err := obj.Compute(a.stateMACer, nil)
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(obj)
}

func (a *AuthN) verifyKEKState(state util.Bytes, uid util.ID) (int64, string, error) {
	obj := &cose.Mac0Message[key.IntMap]{}
	if err := cbor.Unmarshal(state, obj); err != nil {
		return 0, "", err
	}

	if err := obj.Verify(a.stateMACer, nil); err != nil {
		return 0, "", err
	}

	issAt, err := obj.Payload.GetInt64(0)
	if err != nil {
		return 0, "", err
	}

	id, err := obj.Payload.GetBytes(1)
	if err != nil {
		return 0, "", err
	}
	if string(uid.Bytes()) != string(id) {
		return 0, "", gear.ErrBadRequest.WithMsg("invalid state")
	}

	path, err := obj.Payload.GetString(2)
	if err != nil {
		return 0, "", err
	}

	return issAt, path, nil
}
