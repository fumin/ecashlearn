package thunder

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"

	"github.com/fumin/ecashlearn/bip380"
	"github.com/pkg/errors"
	"github.com/tyler-smith/go-bip32"
)

type ExtendedSigningKey struct {
	PrivKey   ed25519.PrivateKey
	ChainCode []byte
}

func NewMasterKey(seed []byte) *ExtendedSigningKey {
	hm := hmac.New(sha512.New, []byte("ed25519 seed"))
	hm.Write(seed)
	hashB := hm.Sum(nil)

	left, right := hashB[:32], hashB[32:]
	privKey := ed25519.NewKeyFromSeed(left)
	esk := &ExtendedSigningKey{PrivKey: privKey, ChainCode: right}
	return esk
}

func (k *ExtendedSigningKey) Derive(index uint32) (*ExtendedSigningKey, error) {
	if index < bip32.FirstHardenedChild {
		return nil, errors.Errorf("%d < %d", index, bip32.FirstHardenedChild)
	}

	hm := hmac.New(sha512.New, k.ChainCode)
	hm.Write([]byte{0})
	hm.Write(k.PrivKey[:32])
	binary.Write(hm, binary.BigEndian, index)
	hashB := hm.Sum(nil)

	left, right := hashB[:32], hashB[32:]
	privKey := ed25519.NewKeyFromSeed(left)
	esk := &ExtendedSigningKey{PrivKey: privKey, ChainCode: right}
	return esk, nil
}

func derive(parent *ExtendedSigningKey, index uint32) (*ExtendedSigningKey, error) {
	child, err := parent.Derive(index)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	return child, nil
}

func (k *ExtendedSigningKey) DerivePath(dpath string) (*ExtendedSigningKey, error) {
	descendant, err := bip380.DeriveKeyAtPath[ExtendedSigningKey](k, dpath, derive)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	return descendant, nil
}

func (k *ExtendedSigningKey) PrivateKey() []byte {
	return k.PrivKey[:32]
}

func (k *ExtendedSigningKey) PublicKey() []byte {
	return k.PrivKey[32:]
}
