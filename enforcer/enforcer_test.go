package enforcer

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"testing"

	"github.com/fumin/ecashlearn/bech32"
	"github.com/fumin/ecashlearn/bip380"
	"github.com/fumin/ecashlearn/bitcoin"
	"github.com/fumin/ecashlearn/blkdat"
	"github.com/fumin/ecashlearn/crypto"
	"github.com/fumin/ecashlearn/script"
	"github.com/fumin/ecashlearn/thunder"
	"github.com/fumin/ecashlearn/util"
)

func TestTrace(t *testing.T) {
	const (
		challenge       = "00148835832e28c816b7acd8fdb19772ab2199603a56"
		thunderSlot     = 9
		l1Mnemonic      = "leisure absorb unfair bunker focus absorb hire famous hurdle describe true monitor"
		thunderMnemonic = "side art direct sausage exit worry minor stomach size zero dinner buzz"

		fpath      = "../data/bitcoind/blk00000.dat"
		enforcerDB = "../data/enforcer/signet.mdb"
	)
	l1ScriptPubKey := func(change, index int) []byte {
		// Change and index definitions are in BIP44.
		// https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
		derivationPath := fmt.Sprintf("m/84'/1'/0'/%d/%d", change, index)
		hrp := bech32.HumanReadablePartTestnet
		privKey, _, err := bip380.WpkhAddress(l1Mnemonic, "", derivationPath, hrp)
		if err != nil {
			panic(fmt.Sprintf("%+v", err))
		}

		witver := 0
		witprog := crypto.Hash160(privKey.PublicKey().Key)
		return bech32.SegwitScriptPubKey(witver, witprog)
	}
	thunderAddr58 := func(index int) []byte {
		addr := thunderAddr(thunderMnemonic, index)
		return []byte(util.Base58.EncodeToString(addr))
	}

	blocks, err := blkdat.Read(fpath, challenge)
	if err != nil {
		t.Errorf("%+v", err)
	}
	txMap := make(map[string]blkdat.Transaction)
	for _, b := range blocks {
		for _, tx := range b.Transaction {
			txMap[hex.EncodeToString(tx.ID())] = tx
		}
	}
	d2 := newD2()
	var l1Coins bitcoin.Amount
	var m3 Message

	for height, b := range blocks {
		ms, err := getMessages(b, txMap)
		if err != nil {
			t.Errorf("%+v", err)
		}
		for i := range ms {
			ms[i].Height = height
		}
		d2Snapshot := d2.snapshot()
		if err := d2.HandleMsgs(ms, height); err != nil {
			t.Errorf("%+v", err)
		}

		// Get coins from faucet.
		if height == 610 {
			faucetDrip := bitcoin.BtcToSats(2.1)
			l1Coins += faucetDrip

			tx := b.Transaction[findTx(b, util.HexD("ed57ebe43810c135b286aebe856bd136e69d3aee03bca14fec863fb4f180ee8e"))]
			o := tx.Output[1]
			if spk := l1ScriptPubKey(0, 0); !bytes.Equal(o.Script, spk) {
				t.Errorf("%x != %x", o.Script, spk)
			}
			if o.Amount != l1Coins {
				t.Errorf("%d != %d", o.Amount, l1Coins)
			}
		}

		// Deposit to thunder.
		if height == 611 {
			depositAmount := bitcoin.BtcToSats(0.03)
			l1Fee := bitcoin.BtcToSats(0.0001)
			l1Coins -= (depositAmount + l1Fee)

			tx := b.Transaction[findTx(b, util.HexD("42f1cdbf2e90a8b045fc8df1c76076f23f0b8909c4fda715e76b2f8bb6002a62"))]
			o := tx.Output[2]
			if spk := l1ScriptPubKey(1, 0); !bytes.Equal(o.Script, spk) {
				t.Errorf("%x != %x", o.Script, spk)
			}
			if o.Amount != l1Coins {
				t.Errorf("%d != %d", o.Amount, l1Coins)
			}

			// Check bip300/301 message.
			m := ms[findMsg[M5](ms)]
			deposit := m.Msg.(M5).Deposits[thunderSlot]
			if a := thunderAddr58(2); !bytes.Equal(deposit.Address, a) {
				t.Errorf("%x != %x", deposit.Address, a)
			}
			if deposit.Value != depositAmount {
				t.Errorf("%d != %d", deposit.Value, depositAmount)
			}
		}

		// Deposit to thunder.
		if height == 617 {
			depositAmount := bitcoin.BtcToSats(0.04)
			l1Fee := bitcoin.BtcToSats(0.0001)
			l1Coins -= (depositAmount + l1Fee)

			tx := b.Transaction[findTx(b, util.HexD("5c632bb85656b27e4a140c5c81def16f36f5652a8b5c2ea413c335c4f3708b77"))]
			o := tx.Output[2]
			if spk := l1ScriptPubKey(1, 1); !bytes.Equal(o.Script, spk) {
				t.Errorf("%x != %x", o.Script, spk)
			}
			if o.Amount != l1Coins {
				t.Errorf("%d != %d", o.Amount, l1Coins)
			}

			// Check bip300/301 message.
			m := ms[findMsg[M5](ms)]
			deposit := m.Msg.(M5).Deposits[thunderSlot]
			if a := thunderAddr58(3); !bytes.Equal(deposit.Address, a) {
				t.Errorf("%x != %x", deposit.Address, a)
			}
			if deposit.Value != depositAmount {
				t.Errorf("%d != %d", deposit.Value, depositAmount)
			}
		}

		// Send coins back to faucet.
		if height == 617 {
			sent := bitcoin.BtcToSats(0.02)
			l1Fee := bitcoin.BtcToSats(0.0001)
			l1Coins -= (sent + l1Fee)

			tx := b.Transaction[findTx(b, util.HexD("2a88963f1efe7c86373aa1dbc48e2dd73664fd5eac2287c020e88969a63f093c"))]
			o := tx.Output[1]
			if spk := l1ScriptPubKey(1, 2); !bytes.Equal(o.Script, spk) {
				t.Errorf("%x != %x", o.Script, spk)
			}
			if o.Amount != l1Coins {
				t.Errorf("%d != %d", o.Amount, l1Coins)
			}
		}

		if height > 617 && height < 626 {
			if i := findMsg[M3](ms); i != -1 {
				m3 = ms[i]
			}
		}

		// Withdraw from thunder.
		if height == 626 {
			withdrawAmount := bitcoin.BtcToSats(0.01)
			l1Fee := bitcoin.BtcToSats(0.0001)
			l1Coins += withdrawAmount
			l1Coins -= l1Fee

			tx := b.Transaction[findTx(b, util.HexD("7a0f201ad434f5d7d23f84a0f276dfc5424634fdea9240f64757aa7f18bacfbf"))]
			o := tx.Output[2]
			if spk := l1ScriptPubKey(1, 2); !bytes.Equal(o.Script, spk) {
				t.Errorf("%x != %x", o.Script, spk)
			}
			if o.Amount != withdrawAmount {
				t.Errorf("%d != %d", o.Amount, withdrawAmount)
			}

			// Check bip300/301 message.
			m := ms[findMsg[M6](ms)]
			m6 := m.Msg.(M6)
			if m6.SidechainN != thunderSlot {
				t.Errorf("%d != %d", m6.SidechainN, thunderSlot)
			}
			// Check that m6 matches m3.
			if slot := m3.Msg.(M3).SidechainN; m6.SidechainN != slot {
				t.Errorf("%d != %d", m6.SidechainN, slot)
			}
			if m6id := m3.Msg.(M3).Bundle; !bytes.Equal(m6.M6, m6id) {
				t.Errorf("%x != %x", m6.M6, m6id)
			}
			// Check m3 matches withdrawal bundle.
			bundle := d2Snapshot[m6.SidechainN][0]
			if m6id := m3.Msg.(M3).Bundle; !bytes.Equal(bundle.M6ID, m6id) {
				t.Errorf("%x != %x", bundle.M6ID, m6id)
			}
			if m3.Height != int(bundle.Info.ProposalHeight) {
				t.Errorf("%d != %d", m3.Height, bundle.Info.ProposalHeight)
			}
			// Check withdrawal bundle has been upvoted.
			if !(int(bundle.Info.Vote) > d2.withdrawalInclusionThreshold) {
				t.Errorf("!(%d > %d)", bundle.Info.Vote, d2.withdrawalInclusionThreshold)
			}
			age := height - int(bundle.Info.ProposalHeight)
			if !(age < d2.withdrawalMaxAge) {
				t.Errorf("!(%d < %d)", age, d2.withdrawalMaxAge)
			}
		}
	}
}

func TestM5(t *testing.T) {
	const (
		fpath     = "../data/bitcoind/blk00000.dat"
		challenge = "00148835832e28c816b7acd8fdb19772ab2199603a56"
	)
	blocks, err := blkdat.Read(fpath, challenge)
	if err != nil {
		t.Errorf("%+v", err)
	}
	txMap := make(map[string]blkdat.Transaction)
	for _, b := range blocks {
		for _, tx := range b.Transaction {
			txMap[hex.EncodeToString(tx.ID())] = tx
		}
	}

	tests := []struct {
		tx  []byte
		msg Message
	}{
		{
			tx: util.HexD("42f1cdbf2e90a8b045fc8df1c76076f23f0b8909c4fda715e76b2f8bb6002a62"),
			msg: Message{
				Transaction: 1,
				Msg: M5{
					Deposits: map[SidechainNumber]Deposit{
						9: Deposit{
							Outpoint: bitcoin.Outpoint{
								TxID: util.HexD("42f1cdbf2e90a8b045fc8df1c76076f23f0b8909c4fda715e76b2f8bb6002a62"),
								Vout: 0,
							},
							Address: []byte(util.Base58.EncodeToString(thunderAddr("side art direct sausage exit worry minor stomach size zero dinner buzz", 2))),
							Value:   bitcoin.BtcToSats(0.03),
						},
					},
					Diff: map[SidechainNumber]Ctip{
						9: Ctip{
							Outpoint: bitcoin.Outpoint{
								TxID: util.HexD("42f1cdbf2e90a8b045fc8df1c76076f23f0b8909c4fda715e76b2f8bb6002a62"),
								Vout: 0,
							},
							Value: bitcoin.BtcToSats(0.59),
						},
					},
				},
			},
		},
		{
			tx: util.HexD("5c632bb85656b27e4a140c5c81def16f36f5652a8b5c2ea413c335c4f3708b77"),
			msg: Message{
				Transaction: 1,
				Msg: M5{
					Deposits: map[SidechainNumber]Deposit{
						9: Deposit{
							Outpoint: bitcoin.Outpoint{
								TxID: util.HexD("5c632bb85656b27e4a140c5c81def16f36f5652a8b5c2ea413c335c4f3708b77"),
								Vout: 0,
							},
							Address: []byte(util.Base58.EncodeToString(thunderAddr("side art direct sausage exit worry minor stomach size zero dinner buzz", 3))),
							Value:   bitcoin.BtcToSats(0.04),
						},
					},
					Diff: map[SidechainNumber]Ctip{
						9: Ctip{
							Outpoint: bitcoin.Outpoint{
								TxID: util.HexD("5c632bb85656b27e4a140c5c81def16f36f5652a8b5c2ea413c335c4f3708b77"),
								Vout: 0,
							},
							Value: bitcoin.BtcToSats(0.63),
						},
					},
				},
			},
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			height := -1
			for i, b := range blocks {
				for _, tx := range b.Transaction {
					if bytes.Equal(tx.ID(), test.tx) {
						height = i
						break
					}
				}
			}
			test.msg.Block = blocks[height]

			ms, err := getMessages(blocks[height], txMap)
			if err != nil {
				t.Errorf("%+v", err)
			}
			m5Idx := findMsg[M5](ms)
			if err := util.JsonEq(ms[m5Idx], test.msg); err != nil {
				t.Errorf("%+v", err)
			}
		})
	}
}

func TestM6(t *testing.T) {
	const (
		fpath     = "../data/bitcoind/blk00000.dat"
		challenge = "00148835832e28c816b7acd8fdb19772ab2199603a56"
	)
	blocks, err := blkdat.Read(fpath, challenge)
	if err != nil {
		t.Errorf("%+v", err)
	}
	txMap := make(map[string]blkdat.Transaction)
	for _, b := range blocks {
		for _, tx := range b.Transaction {
			txMap[hex.EncodeToString(tx.ID())] = tx
		}
	}

	tests := []struct {
		tx  []byte
		msg Message
	}{
		{
			tx: util.HexD("7a0f201ad434f5d7d23f84a0f276dfc5424634fdea9240f64757aa7f18bacfbf"),
			msg: Message{
				Transaction: 1,
				Msg: M6{
					SidechainN: 9,
					M6:         util.HexD("163f404a5a4ab144638393d4f2a541641d834cd50bf174e7e32120e620558960"),
				},
			},
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			height := -1
			for i, b := range blocks {
				for _, tx := range b.Transaction {
					if bytes.Equal(tx.ID(), test.tx) {
						height = i
						break
					}
				}
			}
			test.msg.Block = blocks[height]

			ms, err := getMessages(blocks[height], txMap)
			if err != nil {
				t.Errorf("%+v", err)
			}
			m6Idx := findMsg[M6](ms)
			if err := util.JsonEq(ms[m6Idx], test.msg); err != nil {
				t.Errorf("%+v", err)
			}
		})
	}
}

func TestThunderWallet(t *testing.T) {
	const (
		fpath     = "../data/bitcoind/blk00000.dat"
		challenge = "00148835832e28c816b7acd8fdb19772ab2199603a56"
	)
	blocks, err := blkdat.Read(fpath, challenge)
	if err != nil {
		t.Errorf("%+v", err)
	}
	thunderMnemonic := "side art direct sausage exit worry minor stomach size zero dinner buzz"

	tests := []struct {
		l1tx      string
		l2AddrIdx int
	}{
		{
			l1tx:      "42f1cdbf2e90a8b045fc8df1c76076f23f0b8909c4fda715e76b2f8bb6002a62",
			l2AddrIdx: 2,
		},
		{
			l1tx:      "5c632bb85656b27e4a140c5c81def16f36f5652a8b5c2ea413c335c4f3708b77",
			l2AddrIdx: 3,
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			l1tx, err := blkdat.FindTx(blocks, test.l1tx)
			if err != nil {
				t.Errorf("%+v", err)
			}
			l1txOutIdx := 1
			scriptPubKey, err := script.Decode(l1tx.Output[l1txOutIdx].Script)
			if err != nil {
				t.Errorf("%+v", err)
			}
			opretData := scriptPubKey[1].Data
			l2addr, err := thunder.GetAddress(thunderMnemonic, test.l2AddrIdx)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if l2a := util.Base58.EncodeToString(l2addr); l2a != string(opretData) {
				t.Errorf("%s != %s", l2a, opretData)
			}
		})
	}
}

func thunderAddr(mnemonic string, index int) []byte {
	addr, err := thunder.GetAddress(mnemonic, index)
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
	return addr
}

func findTx(b blkdat.Block, id []byte) int {
	for i, tx := range b.Transaction {
		if bytes.Equal(tx.ID(), id) {
			return i
		}
	}
	return -1
}

func findMsg[T M1 | M2 | M3 | M4 | M5 | M6 | M7 | M8](ms []Message) int {
	for i, m := range ms {
		if _, ok := m.Msg.(T); ok {
			return i
		}
	}
	return -1
}

func TestMain(m *testing.M) {
	flag.Parse()
	log.SetFlags(log.Lmicroseconds | log.Llongfile | log.LstdFlags)

	m.Run()
}
