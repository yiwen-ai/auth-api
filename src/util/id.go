package util

// util 模块不要引入其它内部模块
import (
	"encoding/base64"
	"errors"
	"strconv"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/rs/xid"
)

var ZeroID ID
var JARVIS ID = mustParseID("0000000000000jarvis0") // system user
var ANON ID = mustParseID("000000000000000anon0")   // anonymous user

func NewID() ID {
	return ID(xid.New())
}

func ParseID(s string) (ID, error) {
	id, err := xid.FromString(s)
	if err != nil {
		return ZeroID, err
	}
	return ID(id), nil
}

func TryParseID(s string) *ID {
	id, err := xid.FromString(s)
	if err != nil {
		return nil
	}
	return Ptr(ID(id))
}

func mustParseID(s string) ID {
	id, err := xid.FromString(s)
	if err != nil {
		panic(err)
	}
	return ID(id)
}

type ID xid.ID

func (id *ID) String() string {
	if id == nil {
		return ""
	}

	return xid.ID(*id).String()
}

func (id ID) Bytes() []byte {
	return xid.ID(id).Bytes()
}

func (id ID) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(xid.ID(id).Bytes())
}

func (id *ID) UnmarshalCBOR(data []byte) error {
	if id == nil {
		return errors.New("util.ID.UnmarshalCBOR: nil pointer")
	}

	var buf []byte
	if err := cbor.Unmarshal(data, &buf); err != nil {
		return errors.New("util.ID.UnmarshalCBOR: " + err.Error())
	}

	if bytesLen := len(buf); bytesLen != 12 {
		return errors.New("util.ID.UnmarshalCBOR: invalid bytes length, expected " +
			strconv.Itoa(12) + ", got " + strconv.Itoa(bytesLen))
	}

	copy((*id)[:], buf)
	return nil
}

func (id ID) MarshalJSON() ([]byte, error) {
	return xid.ID(id).MarshalJSON()
}

func (id *ID) UnmarshalJSON(data []byte) error {
	if id == nil {
		return errors.New("util.ID.UnmarshalJSON: nil pointer")
	}
	return (*xid.ID)(id).UnmarshalJSON(data)
}

func (id ID) MarshalText() ([]byte, error) {
	return xid.ID(id).MarshalText()
}

func (id *ID) UnmarshalText(data []byte) error {
	if id == nil {
		return errors.New("util.ID.UnmarshalText: nil pointer")
	}
	return (*xid.ID)(id).UnmarshalText(data)
}

type UUID uuid.UUID

func NewUUID() UUID {
	id, err := uuid.NewUUID()
	if err != nil {
		panic(err)
	}
	return UUID(id)
}

func (id *UUID) String() string {
	if id == nil {
		return ""
	}

	return uuid.UUID(*id).String()
}

func (id UUID) Base64() string {
	return base64.RawURLEncoding.EncodeToString(id[:])
}

func (id UUID) MarshalCBOR() ([]byte, error) {
	data, _ := uuid.UUID(id).MarshalBinary()
	return cbor.Marshal(data)
}

func (id *UUID) UnmarshalCBOR(data []byte) error {
	if id == nil {
		return errors.New("util.UUID.UnmarshalCBOR: nil pointer")
	}

	var buf []byte
	if err := cbor.Unmarshal(data, &buf); err != nil {
		return errors.New("util.UUID.UnmarshalCBOR: " + err.Error())
	}

	if bytesLen := len(buf); bytesLen != 16 {
		return errors.New("util.UUID.UnmarshalCBOR: invalid bytes length, expected " +
			strconv.Itoa(12) + ", got " + strconv.Itoa(bytesLen))
	}

	copy((*id)[:], buf)
	return nil
}

func (id UUID) MarshalText() ([]byte, error) {
	return uuid.UUID(id).MarshalText()
}

func (id *UUID) UnmarshalText(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalText(data)
}

type Bytes []byte

func (r Bytes) String() string {
	return base64.RawURLEncoding.EncodeToString(r)
}

func (r Bytes) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal([]byte(r))
}

func (r *Bytes) UnmarshalCBOR(data []byte) error {
	if r == nil {
		return errors.New("util.Bytes: UnmarshalCBOR on nil pointer")
	}
	cbor.Unmarshal(data, (*[]byte)(r))
	return nil
}

func (r Bytes) MarshalJSON() ([]byte, error) {
	if len(r) == 0 {
		return []byte("null"), nil
	}

	return []byte("\"" + base64.RawURLEncoding.EncodeToString(r) + "\""), nil
}

func (r *Bytes) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("util.Bytes: UnmarshalJSON on nil pointer")
	}
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return errors.New("util.Bytes: UnmarshalJSON with invalid data")
	}
	data, err := base64.RawURLEncoding.DecodeString(string(data[1 : len(data)-1]))
	if err == nil {
		*r = append((*r)[0:0], data...)
	}
	return err
}

func Unmarshal[T any](b *Bytes) (*T, error) {
	if b == nil {
		return nil, errors.New("nil bytes")
	}

	var v T
	if err := cbor.Unmarshal([]byte(*b), &v); err != nil {
		return nil, err
	}
	return &v, nil
}
