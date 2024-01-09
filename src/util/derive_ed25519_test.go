// (c) 2022-present, Yiwen AI, LLC. All rights reserved.
// See the file LICENSE for licensing terms.

package util

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeriveEd25519(t *testing.T) {
	t.Run("DerivePath", func(t *testing.T) {
		assert := assert.New(t)

		for _, path := range []string{"42", "n/0'/0", "4/m/5", "m//3/0'", "m/0h/0x", "m/2147483648"} {
			idxs, err := DerivePath(path)
			assert.Nil(idxs)
			assert.Error(err)
		}

		idxs, err := DerivePath("m")
		assert.Nil(err)
		assert.Equal([]uint32{}, idxs)
		assert.Equal("m", ToDerivePath(idxs))

		idxs, err = DerivePath("m/0'")
		assert.Nil(err)
		assert.Equal([]uint32{0 + HARDENED_OFFSET}, idxs)
		assert.Equal("m/0'", ToDerivePath(idxs))

		idxs, err = DerivePath("m/0'/1")
		assert.Nil(err)
		assert.Equal([]uint32{0 + HARDENED_OFFSET, 1}, idxs)
		assert.Equal("m/0'/1", ToDerivePath(idxs))

		idxs, err = DerivePath("m/0'/1/2'")
		assert.Nil(err)
		assert.Equal([]uint32{0 + HARDENED_OFFSET, 1, 2 + HARDENED_OFFSET}, idxs)
		assert.Equal("m/0'/1/2'", ToDerivePath(idxs))

		idxs, err = DerivePath("m/0'/1/2'/2")
		assert.Nil(err)
		assert.Equal([]uint32{0 + HARDENED_OFFSET, 1, 2 + HARDENED_OFFSET, 2}, idxs)
		assert.Equal("m/0'/1/2'/2", ToDerivePath(idxs))

		idxs, err = DerivePath("m/0'/1/2'/2/1000000000")
		assert.Nil(err)
		assert.Equal([]uint32{0 + HARDENED_OFFSET, 1, 2 + HARDENED_OFFSET, 2, 1000000000}, idxs)
		assert.Equal("m/0'/1/2'/2/1000000000", ToDerivePath(idxs))

		idxs, err = DerivePath("m/0'/50/3'/5/545456")
		assert.Nil(err)
		assert.Equal([]uint32{0 + HARDENED_OFFSET, 50, 3 + HARDENED_OFFSET, 5, 545456}, idxs)
		assert.Equal("m/0'/50/3'/5/545456", ToDerivePath(idxs))
	})

	t.Run("DeriveEd25519", func(t *testing.T) {
		assert := assert.New(t)

		CASE_1_SEED, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

		key := DeriveEd25519(CASE_1_SEED, []uint32{})
		assert.Equal("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7", hex.EncodeToString(key[:]))

		key = DeriveEd25519(CASE_1_SEED, []uint32{0})
		assert.Equal("68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3", hex.EncodeToString(key[:]))

		key = DeriveEd25519(CASE_1_SEED, []uint32{0, 1})
		assert.Equal("b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2", hex.EncodeToString(key[:]))

		key = DeriveEd25519(CASE_1_SEED, []uint32{0, 1, 2})
		assert.Equal("92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9", hex.EncodeToString(key[:]))

		key = DeriveEd25519(CASE_1_SEED, []uint32{0, 1, 2, 2})
		assert.Equal("30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662", hex.EncodeToString(key[:]))

		key = DeriveEd25519(CASE_1_SEED, []uint32{0, 1, 2, 2, 1000000000})
		assert.Equal("8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793", hex.EncodeToString(key[:]))

		assert.Equal(DeriveEd25519(CASE_1_SEED, []uint32{0}), DeriveEd25519(CASE_1_SEED, []uint32{0x80000000}))

		assert.Equal(DeriveEd25519(CASE_1_SEED, []uint32{1}), DeriveEd25519(CASE_1_SEED, []uint32{0x80000001}))

		CASE_2_SEED, _ := hex.DecodeString("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")

		key = DeriveEd25519(CASE_2_SEED, []uint32{})
		assert.Equal("171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012", hex.EncodeToString(key[:]))

		key = DeriveEd25519(CASE_2_SEED, []uint32{0})
		assert.Equal("1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635", hex.EncodeToString(key[:]))

		key = DeriveEd25519(CASE_2_SEED, []uint32{0, 2147483647})
		assert.Equal("ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4", hex.EncodeToString(key[:]))

		key = DeriveEd25519(CASE_2_SEED, []uint32{0, 2147483647, 1})
		assert.Equal("3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c", hex.EncodeToString(key[:]))

		key = DeriveEd25519(CASE_2_SEED, []uint32{0, 2147483647, 1, 2147483646})
		assert.Equal("5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72", hex.EncodeToString(key[:]))

		key = DeriveEd25519(CASE_2_SEED, []uint32{0, 2147483647, 1, 2147483646, 2})
		assert.Equal("551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d", hex.EncodeToString(key[:]))
	})
}
