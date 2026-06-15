package crypto

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"

	"github.com/mndrix/btcutil"
)

// https://karpathy.github.io/2021/06/21/blockchain/
func TestScalarBaseMultKarpathy(t *testing.T) {
	secretKey := big.NewInt(0)
	secretKey = secretKey.SetBytes([]byte("Andrej is cool :P"))
	skDecimal := "22265090479312778178772228083027296664144"
	if sk := secretKey.String(); sk != skDecimal {
		t.Errorf("%s != %s", sk, skDecimal)
	}

	curve := btcutil.Secp256k1()
	publicKeyX, publicKeyY := curve.ScalarBaseMult(secretKey.Bytes())
	pubx := "83998262154709529558614902604110599582969848537757180553516367057821848015989"
	if xs := publicKeyX.String(); xs != pubx {
		t.Errorf("%s != %s", xs, pubx)
	}
	puby := "37676469766173670826348691885774454391218658108212372128812329274086400588247"
	if ys := publicKeyY.String(); ys != puby {
		t.Errorf("%s != %s", ys, puby)
	}
}

func TestScalarBaseMultIter(t *testing.T) {
	curve := btcutil.Secp256k1().(*btcutil.KoblitzCurve)
	for i := 1; i <= 3; i++ {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			// Multiply by iterative addition.
			xAdd, yAdd := curve.Gx, curve.Gy
			for j := 1; j < i; j++ {
				if xAdd.Cmp(curve.Gx) == 0 && yAdd.Cmp(curve.Gy) == 0 {
					xAdd, yAdd = curve.Double(xAdd, yAdd)
					continue
				}
				xAdd, yAdd = curve.Add(xAdd, yAdd, curve.Gx, curve.Gy)
			}

			// Use ScalarBaseMult directly.
			k := make([]byte, 8)
			binary.BigEndian.PutUint64(k, uint64(i))
			xMul, yMul := curve.ScalarBaseMult(k)

			// Check results are the same.
			if xAdd.Cmp(xMul) != 0 {
				t.Errorf("%v != %v", xAdd, xMul)
			}
			if yAdd.Cmp(yMul) != 0 {
				t.Errorf("%v != %v", yAdd, yMul)
			}
		})
	}
}
