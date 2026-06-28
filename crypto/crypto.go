package crypto

import (
	"crypto/sha256"
	"math/big"

	"github.com/mndrix/btcutil"
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

// From utils.go in github.com/tyler-smith/go-bip32
// As described at https://crypto.stackexchange.com/a/8916
func ExpandPublicKey(key []byte) (*big.Int, *big.Int) {
	curveParams := btcutil.Secp256k1().Params()
	Y := big.NewInt(0)
	X := big.NewInt(0)
	X.SetBytes(key[1:])

	// y^2 = x^3 + ax^2 + b
	// a = 0
	// => y^2 = x^3 + b
	ySquared := big.NewInt(0)
	ySquared.Exp(X, big.NewInt(3), nil)
	ySquared.Add(ySquared, curveParams.B)

	Y.ModSqrt(ySquared, curveParams.P)

	Ymod2 := big.NewInt(0)
	Ymod2.Mod(Y, big.NewInt(2))

	signY := uint64(key[0]) - 2
	if signY != Ymod2.Uint64() {
		Y.Sub(curveParams.P, Y)
	}

	return X, Y
}
