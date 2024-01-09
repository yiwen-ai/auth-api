package util

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

const HARDENED_OFFSET = 0x80000000
const ED25519_CURVE = "ed25519 seed"

var DerivePathPrefix = regexp.MustCompile(`^[mM]'?\/?`)

func ToDerivePath(idxs []uint32) string {
	s := strings.Builder{}
	s.WriteRune('m')
	for _, i := range idxs {
		hardened := i >= HARDENED_OFFSET
		if hardened {
			i -= HARDENED_OFFSET
		}
		s.WriteRune('/')
		s.WriteString(strconv.FormatUint(uint64(i), 10))
		if hardened {
			s.WriteRune('\'')
		}
	}

	return s.String()
}

func DerivePath(path string) ([]uint32, error) {
	if !DerivePathPrefix.MatchString(path) {
		return nil, errors.New(`path must start with "m" or "M"`)
	}
	path = DerivePathPrefix.ReplaceAllLiteralString(path, "")
	if len(path) == 0 {
		return []uint32{}, nil
	}

	parts := strings.Split(path, "/")

	idxs := make([]uint32, len(parts))
	for i := 0; i < len(parts); i++ {
		hardened := strings.HasSuffix(parts[i], "'")
		i64, err := strconv.ParseUint(strings.TrimSuffix(parts[i], "'"), 10, 32)
		if err != nil {
			return nil, err
		}
		if i64 >= HARDENED_OFFSET {
			return nil, errors.New("invalid index")
		}

		if hardened {
			i64 += HARDENED_OFFSET
		}
		idxs[i] = uint32(i64)
	}

	// return idxs
	return idxs, nil
}

func NextDerivePath(path string) (string, error) {
	idxs, err := DerivePath(path)
	if err != nil {
		return "", nil
	}
	i := idxs[len(idxs)-1] + 1
	if i >= HARDENED_OFFSET {
		i -= HARDENED_OFFSET
	}
	idxs[len(idxs)-1] = i
	return ToDerivePath(idxs), nil
}

// SLIP-0010 https://github.com/satoshilabs/slips/blob/master/slip-0010.md
func DeriveEd25519(
	seed []byte,
	derivationPath []uint32,
) (priv [32]byte) {
	key, chainCode := getMasterKeyFromSeed(seed)

	for _, idx := range derivationPath {
		key, chainCode = ckdPriv(key, chainCode, idx|HARDENED_OFFSET)
	}
	copy(priv[:], key)
	return
}

func getMasterKeyFromSeed(seed []byte) ([]byte, []byte) {
	mac := hmac.New(sha512.New, []byte(ED25519_CURVE))
	mac.Write(seed)
	data := mac.Sum(nil)
	return data[0:32], data[32:]
}

func ckdPriv(key, chainCode []byte, index uint32) ([]byte, []byte) {
	var b [4]byte

	mac := hmac.New(sha512.New, chainCode)
	mac.Write(b[0:1])
	mac.Write(key)
	binary.BigEndian.PutUint32(b[:], index)
	mac.Write(b[:])
	data := mac.Sum(nil)

	return data[0:32], data[32:]
}
