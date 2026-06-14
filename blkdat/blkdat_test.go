package blkdat

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"testing"

	"github.com/fumin/ecashlearn/crypto"
	"github.com/fumin/ecashlearn/script"
	"github.com/pkg/errors"
)

func TestTrace(t *testing.T) {
	const challenge = "00148835832e28c816b7acd8fdb19772ab2199603a56"
	magic, err := signetMagic(challenge)
	if err != nil {
		t.Errorf("%+v", err)
	}
	fpath := "../data/blk00000.dat"
	blocks, err := read(fpath, magic)
	if err != nil {
		t.Errorf("%+v", err)
	}

	tx0, err := findTx(blocks, "ed57ebe43810c135b286aebe856bd136e69d3aee03bca14fec863fb4f180ee8e")
	if err != nil {
		t.Errorf("%+v", err)
	}
	scriptPubKey, err := script.Decode(tx0.Output[1].Script)
	if err != nil {
		t.Errorf("%+v", err)
	}
	t.Logf("scriptPubKey %#x", scriptPubKey)

	tx1, err := findTx(blocks, "42f1cdbf2e90a8b045fc8df1c76076f23f0b8909c4fda715e76b2f8bb6002a62")
	if err != nil {
		t.Errorf("%+v", err)
	}
	if len(tx1.Input[0].Script) != 0 {
		t.Errorf("%x", tx1.Input[0].Script)
	}
	t.Logf("witness %x", tx1.Input[0].Witness)

	signature := tx1.Input[0].Witness[0]
	pubKey := tx1.Input[0].Witness[1]
	pubKeyHash := scriptPubKey[1].Data
	if pkh := crypto.Hash160(pubKey); !bytes.Equal(pkh, pubKeyHash) {
		t.Errorf("hash160(%x) = %x want %x", pubKey, pkh, pubKeyHash)
	}
	t.Logf("signature %x", signature)
}

func TestHashTx(t *testing.T) {
	tests := []struct {
		tx      Transaction
		nIn     int
		prevOut Output
		sighash byte
		txHash  []byte
	}{
		{
			tx: Transaction{
				Version: 1,
				Input: []Input{
					{
						PrevTx:         hexD("fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"),
						PrevTxOutIndex: 0,
						Sequence:       hexD("eeffffff"),
					},
					{
						PrevTx:         hexD("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a"),
						PrevTxOutIndex: 1,
						Sequence:       hexD("ffffffff"),
					},
				},
				Output: []Output{
					{
						Amount: int(binary.LittleEndian.Uint64(hexD("202cb20600000000"))),
						Script: hexD("1976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac"),
					},
					{
						Amount: int(binary.LittleEndian.Uint64(hexD("9093510d00000000"))),
						Script: hexD("1976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac"),
					},
				},
				Locktime: int(binary.LittleEndian.Uint32(hexD("11000000"))),
			},
			nIn: 1,
			prevOut: Output{
				Amount: crypto.BtcToSatoshi(6),
				Script: hexD("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"),
			},
			sighash: SIGHASH_ALL,
			txHash:  hexD("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"),
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			txHash, err := hashTx(test.tx, test.nIn, test.prevOut, test.sighash)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if !bytes.Equal(txHash, test.txHash) {
				t.Errorf("hashTx() = %x want %x", txHash, test.txHash)
			}
		})
	}
}

func TestRead(t *testing.T) {
	const challenge = "00148835832e28c816b7acd8fdb19772ab2199603a56"
	magic, err := signetMagic(challenge)
	if err != nil {
		t.Errorf("%+v", err)
	}
	fpath := "../data/blk00000.dat"
	blocks, err := read(fpath, magic)
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
		if id := hex.EncodeToString(tx.ID); id != txIDs[i] {
			t.Errorf("tx.ID = %s want %s", id, txIDs[i])
		}
	}
}

func TestMain(m *testing.M) {
	flag.Parse()
	log.SetFlags(log.Lmicroseconds | log.Llongfile | log.LstdFlags)

	m.Run()
}

func findTx(blocks []Block, txIDStr string) (Transaction, error) {
	txID, err := hex.DecodeString(txIDStr)
	if err != nil {
		return Transaction{}, errors.Wrap(err, "")
	}
	for _, b := range blocks {
		for _, tx := range b.Transaction {
			if bytes.Equal(tx.ID, txID) {
				return tx, nil
			}
		}
	}
	return Transaction{}, errors.Errorf("not found")
}

func hexD(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
