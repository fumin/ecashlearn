package blkdat

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/big"
	"testing"

	"github.com/fumin/ecashlearn/bech32"
	"github.com/fumin/ecashlearn/bip380"
	"github.com/fumin/ecashlearn/crypto"
	"github.com/fumin/ecashlearn/script"
	"github.com/fumin/ecashlearn/util"
	"github.com/mndrix/btcutil"
)

func TestTrace(t *testing.T) {
	const (
		fpath     = "../testdata/bitcoind/blk00000.dat"
		challenge = "00148835832e28c816b7acd8fdb19772ab2199603a56"
	)
	blocks, err := Read(fpath, challenge)
	if err != nil {
		t.Errorf("%+v", err)
	}

	type PrivKey struct {
		mnemonic          string
		derivationPath    string
		humanReadablePart string
	}
	tests := []struct {
		tx0       string
		tx0OutIdx int
		outAddr   string
		tx1       string
		tx1InIdx  int
		privKey   PrivKey
	}{
		{
			tx0:       "ed57ebe43810c135b286aebe856bd136e69d3aee03bca14fec863fb4f180ee8e",
			tx0OutIdx: 1,
			outAddr:   "tb1qu7ezehw6ryu5x45cszn47alyhpm0f0z9e8eeaf",
			tx1:       "42f1cdbf2e90a8b045fc8df1c76076f23f0b8909c4fda715e76b2f8bb6002a62",
			tx1InIdx:  0,
			privKey: PrivKey{
				mnemonic:          "leisure absorb unfair bunker focus absorb hire famous hurdle describe true monitor",
				derivationPath:    "m/84'/1'/0'/0/0",
				humanReadablePart: bech32.HumanReadablePartTestnet,
			},
		},
		{
			tx0:       "42f1cdbf2e90a8b045fc8df1c76076f23f0b8909c4fda715e76b2f8bb6002a62",
			tx0OutIdx: 2,
			outAddr:   "tb1qffa2erlg76h4vj7tf4jycx625wwzn0lta0p67z",
			tx1:       "5c632bb85656b27e4a140c5c81def16f36f5652a8b5c2ea413c335c4f3708b77",
			tx1InIdx:  0,
			privKey: PrivKey{
				mnemonic:          "leisure absorb unfair bunker focus absorb hire famous hurdle describe true monitor",
				derivationPath:    "m/84'/1'/0'/1/0",
				humanReadablePart: bech32.HumanReadablePartTestnet,
			},
		},
		{
			tx0:       "5c632bb85656b27e4a140c5c81def16f36f5652a8b5c2ea413c335c4f3708b77",
			tx0OutIdx: 2,
			outAddr:   "tb1qrfe35dakhev25mvqjyxajj2v8yq2ldfyxkejcp",
			tx1:       "2a88963f1efe7c86373aa1dbc48e2dd73664fd5eac2287c020e88969a63f093c",
			tx1InIdx:  0,
			privKey: PrivKey{
				mnemonic:          "leisure absorb unfair bunker focus absorb hire famous hurdle describe true monitor",
				derivationPath:    "m/84'/1'/0'/1/1",
				humanReadablePart: bech32.HumanReadablePartTestnet,
			},
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			// Find transactions.
			tx0, err := FindTx(blocks, test.tx0)
			if err != nil {
				t.Errorf("%+v", err)
			}
			tx1, err := FindTx(blocks, test.tx1)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if len(tx1.Input[test.tx1InIdx].Script) != 0 {
				t.Errorf("%x", tx1.Input[test.tx1InIdx].Script)
			}

			// Check public keys are the same between tx0 and tx1.
			scriptPubKey, err := script.Decode(tx0.Output[test.tx0OutIdx].Script)
			if err != nil {
				t.Errorf("%+v", err)
			}
			pubKey := tx1.Input[test.tx1InIdx].Witness[1]
			pubKeyHash := scriptPubKey[1].Data
			if pkh := crypto.Hash160(pubKey); !bytes.Equal(pkh, pubKeyHash) {
				t.Errorf("hash160(%x) = %x want %x", pubKey, pkh, pubKeyHash)
			}
			epk := &ecdsa.PublicKey{Curve: btcutil.Secp256k1()}
			epk.X, epk.Y = crypto.ExpandPublicKey(pubKey)

			// Extract signature of tx1 input.
			signature := tx1.Input[test.tx1InIdx].Witness[0]
			signature, sigHashType := signature[:len(signature)-1], int(signature[len(signature)-1])
			sigR, sigS, err := parseSignature(signature)
			if err != nil {
				t.Errorf("%+v", err)
			}

			// Verify tx1 input.
			txHash, err := hashTx(tx1, test.tx1InIdx, tx0.Output[test.tx0OutIdx], sigHashType)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if !ecdsa.VerifyASN1(epk, txHash, signature) {
				t.Errorf("not verified")
			}
			if !ecdsa.Verify(epk, txHash, sigR, sigS) {
				t.Errorf("not verified")
			}

			// Check address from output of tx0.
			const hrp = bech32.HumanReadablePartTestnet
			witver := int(scriptPubKey[0].Opcode)
			addr, err := bech32.SegwitAddrEncode(hrp, witver, pubKeyHash)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if addr != test.outAddr {
				t.Errorf("%s != %s", addr, test.outAddr)
			}
			// Check address from private key of tx0 output.
			privKey, derivedAddr, err := bip380.WpkhAddress(test.privKey.mnemonic, "", test.privKey.derivationPath, test.privKey.humanReadablePart)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if derivedAddr != test.outAddr {
				t.Errorf("%s != %s", derivedAddr, test.outAddr)
			}
			if pk := privKey.PublicKey().Key; !bytes.Equal(pubKey, pk) {
				t.Errorf("%x != %x", pubKey, pk)
			}

			// Check that we can sign the transactions.
			pvk := &ecdsa.PrivateKey{
				PublicKey: *epk,
				D:         new(big.Int).SetBytes(privKey.Key),
			}
			sig, err := ecdsa.SignASN1(rand.Reader, pvk, txHash)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if !ecdsa.VerifyASN1(epk, txHash, sig) {
				t.Errorf("not verified")
			}
		})
	}
}

// https://learnmeabitcoin.com/technical/keys/signature/#der
func TestParseSignature(t *testing.T) {
	signature := util.HexD("3045022100e8ce5ac57296580865f3fb8cacf14c76dc8616101c909c5d806881554ae54847022013ae2cd48aa2ab3719a80a8b86d9392772aeffc3d155547313b62156be3b9709")
	r, s, err := parseSignature(signature)
	if err != nil {
		t.Errorf("%+v", err)
	}
	rWant := "105301177847010302988301927997000137281201569527553486684628369573050742818887"
	if rStr := r.String(); rStr != rWant {
		t.Errorf("%s != %s", rStr, rWant)
	}
	sWant := "8901684919301466790290594114920701415032079889826540036574017810850102613769"
	if sStr := s.String(); sStr != sWant {
		t.Errorf("%s != %s", sStr, sWant)
	}
}

func TestHashTx(t *testing.T) {
	tests := []struct {
		rawTx    []byte
		nIn      int
		output   Output
		hashType int
		hash     []byte
	}{
		// https://learnmeabitcoin.com/technical/keys/signature/#segwit-algorithm
		{
			rawTx:    util.HexD("02000000000101ac4994014aa36b7f53375658ef595b3cb2891e1735fe5b441686f5e53338e76a0100000000ffffffff01204e0000000000001976a914ce72abfd0e6d9354a660c18f2825eb392f060fdc88ac02473044022008f4f37e2d8f74e18c1b8fde2374d5f28402fb8ab7fd1cc5b786aa40851a70cb022032b1374d1a0f125eae4f69d1bc0b7f896c964cfdba329f38a952426cf427484c012103eed0d937090cae6ffde917de8a80dc6156e30b13edd5e51e2e50d52428da1c8700000000"),
			nIn:      0,
			output:   Output{Amount: 30000, Script: util.HexD("0014aa966f56de599b4094b61aa68a2b3df9e97e9c48")},
			hashType: SIGHASH_ALL,
			hash:     util.HexD("d7b60220e1b9b2c1ab40845118baf515203f7b6f0ad83cbb68d3c89b5b3098a6"),
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			txParser := &parser{}
			tx := txParser.readTransaction(test.rawTx)
			if txParser.err != nil {
				t.Errorf("%+v", txParser.err)
			}
			txH, err := hashTx(tx, test.nIn, test.output, test.hashType)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if !bytes.Equal(txH, test.hash) {
				t.Errorf("hashTx() = %x want %x", txH, test.hash)
			}
		})
	}
}

func TestBlockHeight(t *testing.T) {
	const (
		fpath     = "../testdata/bitcoind/blk00000.dat"
		challenge = "00148835832e28c816b7acd8fdb19772ab2199603a56"
	)
	blocks, err := Read(fpath, challenge)
	if err != nil {
		t.Errorf("%+v", err)
	}
	for h, b := range blocks {
		if h <= 16 {
			continue
		}
		height, err := b.Height()
		if err != nil {
			t.Errorf("%+v", err)
		}
		if height != h {
			t.Errorf("%d != %d", height, h)
		}
	}

	tests := []struct {
		b      []byte
		height int
	}{
		{b: util.HexD("03c027090004ff52aa5d042b05083008a6e7b35c6e202a00092f426974667572792f"), height: 600000},
		{b: util.HexD("03bc970e1d506f7765726564206279204c75786f7220546563682d008506850ddb47fabe6d6d71df935f6146cac287c2c05ccb1ce9646525933efbdf0af1c0ff29d7bb38609410000000000000000000362600c7000000000002"), height: 956348},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			height, err := parseHeight(test.b)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if height != test.height {
				t.Errorf("%d != %d", height, test.height)
			}
		})
	}
}

func TestRead(t *testing.T) {
	const (
		fpath     = "../testdata/bitcoind/blk00000.dat"
		challenge = "00148835832e28c816b7acd8fdb19772ab2199603a56"
	)
	blocks, err := Read(fpath, challenge)
	if err != nil {
		t.Errorf("%+v", err)
	}

	// Check genesis block.
	b0want := "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
	if b0 := hex.EncodeToString(blocks[0].Hash); b0 != b0want {
		t.Errorf("blocks[0] = %s want %s", b0, b0want)
	}
	m0want := "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
	if m0 := hex.EncodeToString(blocks[0].Header.MerkleRoot); m0 != m0want {
		t.Errorf("blocks[0] = %s want %s", m0, m0want)
	}

	// Check block at height 456.
	b456want := "000002999dfc5ed56bea58726a4479082a55762779db9183b0c781f9818de89a"
	if b456 := hex.EncodeToString(blocks[456].Hash); b456 != b456want {
		t.Errorf("blocks[456] = %s want %s", b456, b456want)
	}
	txIDs := []string{
		"bd6a3c360fc71c8613ba07a4afd7a3cd0cdf91c80531f5a6d6450cb6c21dca4f",
		"05a92f92f70447dd1295db4aa74ba5bff8808319d2c7e784378fa701c4045a45",
		"7e46723c5b574912f565ceed0f7490d80ac5a43b78f1debc81cde30ab13a8bff",
		"6704a6af112a5972311a2cf2d4202454e5cf54b358a3b18d478e1604cba36a67",
	}
	for i, tx := range blocks[456].Transaction {
		if id := hex.EncodeToString(tx.ID()); id != txIDs[i] {
			t.Errorf("tx.ID = %s want %s", id, txIDs[i])
		}
	}
}

func TestMain(m *testing.M) {
	flag.Parse()
	log.SetFlags(log.Lmicroseconds | log.Llongfile | log.LstdFlags)

	m.Run()
}
