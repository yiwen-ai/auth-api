package main

import (
	"encoding/base64"
	"flag"
	"os"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/ldclabs/cose/key/hmac"
)

var kind = flag.String("kind", "state", "generate key for kind")
var out = flag.String("out", "./keys/out.key", "write key to a file")

func main() {
	flag.Parse()

	var err error
	var k key.Key
	var data []byte

	switch *kind {
	case "state":
		k, err = hmac.GenerateKey(iana.AlgorithmHMAC_256_64)
	default:
		panic("unsupported kind")
	}

	if err == nil {
		// data, err = k.MarshalCBOR()
		data, err = cbor.Marshal(cbor.Tag{
			Number:  55799, // self described CBOR Tag
			Content: k,
		})
	}

	if err == nil {
		err = os.WriteFile(*out, []byte(base64.RawURLEncoding.EncodeToString(data)), 0644)
	}

	if err != nil {
		panic(err)
	}
}
