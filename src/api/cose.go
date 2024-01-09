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
	Key       key.Key    `json:"key" cbor:"key"` // private key
	State     util.Bytes `json:"state" cbor:"state"`
	PrevKey   *key.Key   `json:"prev_key" cbor:"prev_key"` // private key
	PrevStale bool       `json:"prev_stale" cbor:"prev_stale"`
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

	var prevKey *key.Key
	path := DEFAULT_PATH
	stale := false
	if input.State != nil {
		issAt, p, err := a.verifyKEKState(*input.State, *sess.UID)
		if err != nil {
			return gear.ErrBadRequest.From(err)
		}
		path, err = util.NextDerivePath(p)
		if err != nil {
			return gear.ErrBadRequest.From(err)
		}
		stale = time.Now().Unix()-issAt > 3600*24

		prev, err := a.blls.Session.DeriveUserKey(ctx, *sess.UID, p)
		if err != nil {
			return gear.ErrInternalServerError.From(err)
		}

		if err := cbor.Unmarshal(prev, prevKey); err != nil {
			return gear.ErrInternalServerError.From(err)
		}

		verifier, err := ed25519.NewVerifier(*prevKey)
		if err != nil {
			return gear.ErrBadRequest.From(err)
		}
		if err := verifier.Verify(*input.State, *input.Sig); err != nil {
			return gear.ErrBadRequest.From(err)
		}
	}

	output, err := a.blls.Session.DeriveUserKey(ctx, *sess.UID, path)
	if err != nil {
		return gear.ErrInternalServerError.From(err)
	}
	var key key.Key
	if err := cbor.Unmarshal(output, &key); err != nil {
		return gear.ErrInternalServerError.From(err)
	}

	state, err := a.createKEKState(*sess.UID, path)
	if err != nil {
		return gear.ErrInternalServerError.From(err)
	}

	return ctx.OkSend(RenewKEKOutput{
		Key:       key,
		State:     state,
		PrevKey:   prevKey,
		PrevStale: stale,
	})
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
