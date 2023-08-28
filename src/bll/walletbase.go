package bll

import (
	"context"
	"math"

	"github.com/fxamacker/cbor/v2"
	"github.com/yiwen-ai/auth-api/src/service"
	"github.com/yiwen-ai/auth-api/src/util"
)

type Walletbase struct {
	svc service.APIHost
}

type AwardInput struct {
	Payee       util.ID    `json:"payee" cbor:"payee"`
	Amount      int64      `json:"amount" cbor:"amount"`
	Credits     uint64     `json:"credits" cbor:"credits"`
	Description string     `json:"description,omitempty" cbor:"description,omitempty"`
	Payload     util.Bytes `json:"payload,omitempty" cbor:"payload,omitempty"`
}

type AwardPayload struct {
	Referrer *util.ID `json:"referrer,omitempty" cbor:"referrer,omitempty"`
}

type WalletOutput struct {
	Sequence uint64  `json:"sequence" cbor:"sequence"`
	Award    int64   `json:"award" cbor:"award"`
	Topup    int64   `json:"topup" cbor:"topup"`
	Income   int64   `json:"income" cbor:"income"`
	Credits  uint64  `json:"credits" cbor:"credits"`
	Level    uint8   `json:"level" cbor:"level"`
	Txn      util.ID `json:"txn" cbor:"txn"`
}

func (w *WalletOutput) Balance() int64 {
	return w.Award + w.Topup + w.Income
}

func (w *WalletOutput) SetLevel() {
	if w.Credits > 0 {
		w.Level = uint8(math.Floor(math.Log10(float64(w.Credits))))
	}
}

func (b *Walletbase) Get(ctx context.Context, uid util.ID) (*WalletOutput, error) {
	output := SuccessResponse[WalletOutput]{}
	if err := b.svc.Get(ctx, "/v1/wallet?uid="+uid.String(), &output); err != nil {
		return nil, err
	}
	output.Result.SetLevel()
	return &output.Result, nil
}

func (b *Walletbase) AwardRegistration(ctx context.Context, uid util.ID, input *AwardPayload) (*WalletOutput, error) {
	data, err := cbor.Marshal(input)
	if err != nil {
		return nil, err
	}

	in := AwardInput{
		Payee:       uid,
		Amount:      100,
		Description: "Registration bonus",
		Payload:     data,
	}
	output := SuccessResponse[WalletOutput]{}
	if err := b.svc.Post(ctx, "/v1/wallet/award", in, &output); err != nil {
		return nil, err
	}

	output.Result.SetLevel()
	return &output.Result, nil
}
