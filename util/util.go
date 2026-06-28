package util

import (
	"encoding/hex"
	"encoding/json"

	"github.com/FactomProject/basen"
	"github.com/pkg/errors"
)

var (
	Base58 = basen.NewEncoding("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
)

func HexD(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func Base58D(s string) []byte {
	b, err := Base58.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func JsonEq(a, b interface{}) error {
	aj, err := json.Marshal(a)
	if err != nil {
		return errors.Wrap(err, "")
	}
	bj, err := json.Marshal(b)
	if err != nil {
		return errors.Wrap(err, "")
	}

	for i, ai := range aj {
		if i >= len(bj) {
			ab, bb := prefixAt(i, aj, bj)
			return errors.Errorf("at %d %x\"%s\" != %x\"%s\"", i, ab, ab, bb, bb)
		}
		bi := bj[i]
		if ai != bi {
			ab, bb := prefixAt(i, aj, bj)
			return errors.Errorf("at %d %x\"%s\" != %x\"%s\"", i, ab, ab, bb, bb)
		}
	}
	if len(aj) != len(bj) {
		return errors.Errorf("%d != %d", len(aj), len(bj))
	}
	return nil
}

func prefixAt(i int, a, b []byte) ([]byte, []byte) {
	start := max(i-32, 0)
	return a[start : i+1], b[start : i+1]
}
