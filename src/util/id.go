package util

// util 模块不要引入其它内部模块
import (
	"errors"
	"strconv"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/rs/xid"
)

var JARVIS ID = mustParseID("0000000000000jarvis0") // system user
var ANON ID = mustParseID("000000000000000anon0")   // anonymous user

func mustParseID(s string) ID {
	id, err := xid.FromString(s)
	if err != nil {
		panic(err)
	}
	return ID(id)
}

type ID xid.ID

func (id ID) String() string {
	return xid.ID(id).String()
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
	return (*xid.ID)(id).UnmarshalJSON(data)
}

type UUID uuid.UUID

func (id UUID) String() string {
	return uuid.UUID(id).String()
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
