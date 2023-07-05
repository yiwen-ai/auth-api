// (c) 2022-present, Yiwen AI, LLC. All rights reserved.
// See the file LICENSE for licensing terms.

package util

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestID(t *testing.T) {
	t.Run("CBOR", func(t *testing.T) {
		assert := assert.New(t)

		data, err := cbor.Marshal(JARVIS)
		assert.NoError(err)
		var id ID
		assert.NoError(cbor.Unmarshal(data, &id))
		assert.Equal(JARVIS, id)
	})

	t.Run("JSON", func(t *testing.T) {
		assert := assert.New(t)

		data, err := json.Marshal(ANON)
		assert.NoError(err)
		assert.Equal(`"000000000000000anon0"`, string(data))
		var id ID
		assert.NoError(json.Unmarshal(data, &id))
		assert.Equal(ANON, id)
	})
}

func TestUUID(t *testing.T) {
	uid := UUID(uuid.Must(uuid.NewUUID()))
	t.Run("CBOR", func(t *testing.T) {
		assert := assert.New(t)

		data, err := cbor.Marshal(uid)
		assert.NoError(err)
		var id UUID
		assert.NoError(cbor.Unmarshal(data, &id))
		assert.Equal(uid, id)
	})

	t.Run("JSON", func(t *testing.T) {
		assert := assert.New(t)

		data, err := json.Marshal(uid)
		assert.NoError(err)
		assert.Equal(strconv.Quote(uid.String()), string(data))
		var id UUID
		assert.NoError(json.Unmarshal(data, &id))
		assert.Equal(uid, id)
	})
}
