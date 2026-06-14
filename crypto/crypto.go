package crypto

import (
	"crypto/sha256"

	"golang.org/x/crypto/ripemd160"
)

func Hash160(b []byte) []byte {
	s256 := sha256.New()
	s256.Write(b)
	b = s256.Sum(nil)

	r160 := ripemd160.New()
	r160.Write(b)
	b = r160.Sum(nil)

	return b
}

func DoubleSha256(data []byte) []byte {
	b0 := sha256.Sum256(data)
	b1 := sha256.Sum256(b0[:])
	return b1[:]
}

func BtcToSatoshi(btc float64) int {
	return int(btc * 1e8)
}
