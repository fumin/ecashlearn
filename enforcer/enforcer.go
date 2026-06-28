package enforcer

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"maps"
	"slices"

	"github.com/fumin/ecashlearn/bitcoin"
	"github.com/fumin/ecashlearn/blkdat"
	"github.com/fumin/ecashlearn/enforcer/types"
	"github.com/fumin/ecashlearn/script"
	"github.com/fumin/ecashlearn/util/bincode"
	"github.com/pkg/errors"
)

const (
	OP_DRIVECHAIN = script.OP_NOP5
)

type M1 struct {
	SidechainN  SidechainNumber
	Description []byte
}

type M2 struct {
	SidechainN  SidechainNumber
	Description [sha256.Size]byte
}

type M3 struct {
	SidechainN SidechainNumber
	Bundle     types.M6ID
}

const (
	M4VersionRepeatPrevious = 0
	M4VersionOneByte        = 1
	M4VersionTwoByte        = 2
	M4VersionLeadingBy50    = 3
)

type M4 struct {
	Enum           bincode.Enum `borsh_enum:"true"`
	RepeatPrevious struct{}
	OneByte        []uint8
	TwoByte        []uint16
	LeadingBy50    struct{}
}

type M5 struct {
	Deposits map[SidechainNumber]Deposit
	Diff     map[SidechainNumber]Ctip
}

type M6 struct {
	SidechainN SidechainNumber
	M6         types.M6ID
}

type M7 struct {
	SidechainN     SidechainNumber
	SidechainBlock BmmCommitment
}

type M8 struct {
	SidechainN     SidechainNumber
	SidechainBlock BmmCommitment
	PrevMainBlock  bitcoin.BlockHash
}

type SidechainNumber = byte

type BmmCommitment = [32]byte

type Deposit struct {
	Outpoint bitcoin.Outpoint
	Address  []byte
	Value    bitcoin.Amount
}

type Ctip struct {
	Outpoint bitcoin.Outpoint
	Value    bitcoin.Amount
}

func parseM1(b []byte) (M1, error) {
	if len(b) < 1 {
		return M1{}, errors.Errorf("%d < 1", len(b))
	}
	var m M1
	m.SidechainN = b[0]
	m.Description = b[1:]
	return m, nil
}

func parseM2(b []byte) (M2, error) {
	if len(b) != 33 {
		return M2{}, errors.Errorf("%d != 33", len(b))
	}
	var m M2
	m.SidechainN = b[0]
	m.Description = [32]byte(b[1:])
	return m, nil
}

func parseM3(b []byte) (M3, error) {
	if len(b) != 33 {
		return M3{}, errors.Errorf("%d != 33", len(b))
	}
	var m M3
	m.SidechainN = b[0]
	m.Bundle = types.M6ID(b[1:])
	return m, nil
}

func parseM4(b []byte) (M4, error) {
	if len(b) < 1 {
		return M4{}, errors.Errorf("%d < 1", len(b))
	}
	var m M4
	m.Enum = bincode.Enum(b[0])
	b = b[1:]
	switch m.Enum {
	case M4VersionRepeatPrevious:
		if len(b) != 0 {
			return M4{}, errors.Errorf("%d != 0", len(b))
		}
	case M4VersionOneByte:
		m.OneByte = make([]uint8, len(b))
		copy(m.OneByte, b)
	case M4VersionTwoByte:
		for i := 0; i < len(b); i += 2 {
			if i+2 > len(b) {
				return M4{}, errors.Errorf("%d > %d", i+2, len(b))
			}
			b2 := b[i : i+2]
			vote := binary.LittleEndian.Uint16(b2)
			m.TwoByte = append(m.TwoByte, vote)
		}
	case M4VersionLeadingBy50:
		if len(b) != 0 {
			return M4{}, errors.Errorf("%d != 0", len(b))
		}
	}
	return m, nil
}

func parseM7(b []byte) (M7, error) {
	if len(b) != 33 {
		return M7{}, errors.Errorf("%d != 33", len(b))
	}
	var m M7
	m.SidechainN = b[0]
	m.SidechainBlock = BmmCommitment(b[1:])
	return m, nil
}

func parseCoinbaseBody(b []byte) (interface{}, error) {
	var m interface{}
	var err error
	switch {
	case bytes.HasPrefix(b, []byte{0xd5, 0xe0, 0xc4, 0xaf}):
		m, err = parseM1(b[4:])
	case bytes.HasPrefix(b, []byte{0xd6, 0xe1, 0xc5, 0xbf}):
		m, err = parseM2(b[4:])
	case bytes.HasPrefix(b, []byte{0xd4, 0x5a, 0xa9, 0x43}):
		m, err = parseM3(b[4:])
	case bytes.HasPrefix(b, []byte{0xd7, 0x7d, 0x17, 0x76}):
		m, err = parseM4(b[4:])
	case bytes.HasPrefix(b, []byte{0xd1, 0x61, 0x73, 0x68}):
		m, err = parseM7(b[4:])
	default:
		err = errors.Errorf("unknown")
	}
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	return m, nil
}

type Message struct {
	Block       blkdat.Block
	Height      int
	Transaction int
	Output      int
	Msg         interface{}
}

type InvalidateBlockError struct {
	e string
}

func (e InvalidateBlockError) Error() string {
	return e.e
}

func checkBlockValidity(messages []Message) error {
	// If another valid M2 message is included within any coinbase output at a lower output index, the block is invalid and MUST be rejected.
	// https://github.com/LayerTwo-Labs/bip300_bip301_specifications/blob/537ab3c7587fe835b6ab795ceab0ecfa70242fa4/bip300.md#semantics-1
	var numM2 int
	for _, m := range messages {
		if _, ok := m.Msg.(M2); ok {
			numM2++
			if numM2 >= 2 {
				return InvalidateBlockError{e: "duplicate M2"}
			}
		}
	}

	// If any of the following conditions hold, the block is considered invalid and MUST be rejected:
	// Another valid M3 message with an identical sidechain slot number is included within any coinbase output at a lower output index.
	// https://github.com/LayerTwo-Labs/bip300_bip301_specifications/blob/537ab3c7587fe835b6ab795ceab0ecfa70242fa4/bip300.md#semantics-2
	numM3 := make(map[SidechainNumber]int)
	for _, m := range messages {
		m3, ok := m.Msg.(M3)
		if ok {
			numM3[m3.SidechainN]++
			if numM3[m3.SidechainN] >= 2 {
				return InvalidateBlockError{e: fmt.Sprintf("duplicate M3 for sidechain %d", m3.SidechainN)}
			}
		}
	}

	// If an M4 has the version VOTES_TWO_BYTES and there are no elements in its A array which are greater than 253, then this M4 along with the block it is included in MUST be considered invalid, because it is wasting bytes by using the 16 bit version when the 8 bit version would suffice.
	// https://github.com/LayerTwo-Labs/bip300_bip301_specifications/blob/537ab3c7587fe835b6ab795ceab0ecfa70242fa4/bip300.md#encoding-3
	for _, m := range messages {
		m4, ok := m.Msg.(M4)
		if ok {
			if m4.Enum == M4VersionTwoByte {
				largeEnough := false
				for _, v := range m4.TwoByte {
					if v > 253 {
						largeEnough = true
						break
					}
				}
				if !largeEnough {
					return InvalidateBlockError{e: "M4 wasting bytes"}
				}
			}
		}
	}

	// If a mainchain block contains an more than one M7 with the same sidechain slot S, then that block MUST be considered invalid.
	// https://github.com/LayerTwo-Labs/bip300_bip301_specifications/blob/598d642e20d0f1505f5b56aa0a2682e18f87c001/bip301.md#validation-rules
	numM7 := make(map[SidechainNumber]int)
	for _, m := range messages {
		m7, ok := m.Msg.(M7)
		if ok {
			numM7[m7.SidechainN]++
			if numM7[m7.SidechainN] >= 2 {
				return InvalidateBlockError{e: fmt.Sprintf("duplicate M7 for sidechain %d", m7.SidechainN)}
			}

		}
	}

	return nil
}

func parseCoinbase(coinbase blkdat.Transaction) ([]Message, error) {
	messages := make([]Message, 0)
	for i, o := range coinbase.Output {
		m := Message{Transaction: 0, Output: i}
		instrcs, err := script.Decode(o.Script)
		if err != nil {
			continue
		}
		if len(instrcs) != 2 {
			continue
		}
		if instrcs[0].Opcode != script.OP_RETURN {
			continue
		}
		b := instrcs[1].Data

		m.Msg, err = parseCoinbaseBody(b)
		if err != nil {
			continue
		}
		messages = append(messages, m)
	}

	if err := checkBlockValidity(messages); err != nil {
		return nil, errors.Wrap(err, "")
	}

	return messages, nil
}

func treasuryUtxoSidechain(spk []byte) (SidechainNumber, error) {
	instrcs, err := script.Decode(spk)
	if err != nil {
		return 0, errors.Wrap(err, "")
	}
	if len(instrcs) != 3 {
		return 0, errors.Errorf("%d != 3", len(instrcs))
	}
	if instrcs[0].Opcode != OP_DRIVECHAIN {
		return 0, errors.Errorf("%d != %d", instrcs[0].Opcode, OP_DRIVECHAIN)
	}
	if len(instrcs[1].Data) != 1 {
		return 0, errors.Errorf("%d != 1", len(instrcs[1].Data))
	}
	if instrcs[2].Opcode != script.OP_TRUE {
		return 0, errors.Errorf("%d != %d", instrcs[2].Opcode, script.OP_TRUE)
	}
	var sidechainN SidechainNumber = instrcs[1].Data[0]
	return sidechainN, nil
}

func parseTxOutput(tx blkdat.Transaction) (map[SidechainNumber]Ctip, error) {
	newCtips := make(map[SidechainNumber]Ctip)
	for i, output := range tx.Output {
		sidechainN, err := treasuryUtxoSidechain(output.Script)
		if err != nil {
			continue
		}

		ctip := Ctip{
			Outpoint: bitcoin.Outpoint{TxID: tx.ID(), Vout: uint32(i)},
			Value:    output.Amount,
		}
		if prev, ok := newCtips[sidechainN]; ok {
			return nil, errors.Errorf("duplicate OP_DRIVECHAIN for sidechain %d in outputs %d and %d", sidechainN, prev.Outpoint.Vout, i)
		}
		newCtips[sidechainN] = ctip
	}
	return newCtips, nil
}

func parseTxInput(tx blkdat.Transaction, txMap map[string]blkdat.Transaction) (map[SidechainNumber]Ctip, error) {
	oldCtips := make(map[SidechainNumber]Ctip)
	for i, input := range tx.Input {
		prevTxID := make([]byte, len(input.PrevOut.TxID))
		copy(prevTxID, input.PrevOut.TxID)
		slices.Reverse(prevTxID)
		prevTx, ok := txMap[hex.EncodeToString(prevTxID)]
		if !ok {
			return nil, errors.Errorf("input %d transaction %x not found", i, input.PrevOut.TxID)
		}
		if int(input.PrevOut.Vout) >= len(prevTx.Output) {
			return nil, errors.Errorf("%d >= %d", input.PrevOut.Vout, len(prevTx.Output))
		}
		prevOut := prevTx.Output[input.PrevOut.Vout]
		oldValue := prevOut.Amount

		sidechainN, err := treasuryUtxoSidechain(prevOut.Script)
		if err != nil {
			continue
		}

		ctip := Ctip{
			Outpoint: bitcoin.Outpoint{TxID: tx.ID(), Vout: uint32(i)},
			Value:    oldValue,
		}
		if prev, ok := oldCtips[sidechainN]; ok {
			return nil, errors.Errorf("duplicate OP_DRIVECHAIN for sidechain %d in outputs %d and %d", sidechainN, prev.Outpoint.Vout, i)
		}
		oldCtips[sidechainN] = ctip
	}
	return oldCtips, nil
}

func parseM5(tx blkdat.Transaction, txMap map[string]blkdat.Transaction) (M5, error) {
	newCtips, err := parseTxOutput(tx)
	if err != nil {
		return M5{}, errors.Wrap(err, "")
	}
	oldCtips, err := parseTxInput(tx, txMap)
	if err != nil {
		return M5{}, errors.Wrap(err, "")
	}

	m5 := M5{
		Deposits: make(map[SidechainNumber]Deposit),
		Diff:     make(map[SidechainNumber]Ctip),
	}
	for sidechainN, ctip := range newCtips {
		oldCtip, ok := oldCtips[sidechainN]
		if !ok {
			return M5{}, errors.Errorf("sidechain %d input not found", sidechainN)
		}
		oldTreasuryValue := oldCtip.Value

		// Parse address.
		nextOidx := ctip.Outpoint.Vout + 1
		instrcs, err := script.Decode(tx.Output[nextOidx].Script)
		if err != nil {
			return M5{}, errors.Wrap(err, "")
		}
		if len(instrcs) != 2 {
			return M5{}, errors.Errorf("%d != 2", len(instrcs))
		}
		if instrcs[0].Opcode != script.OP_RETURN {
			return M5{}, errors.Errorf("%d != %d", instrcs[0].Opcode, script.OP_RETURN)
		}
		address := instrcs[1].Data

		if ctip.Value < oldTreasuryValue {
			return M5{}, errors.Errorf("%d < %d", ctip.Value, oldTreasuryValue)
		}
		deposit := Deposit{
			Outpoint: ctip.Outpoint,
			Address:  address,
			Value:    ctip.Value - oldTreasuryValue,
		}
		m5.Deposits[sidechainN] = deposit
		m5.Diff[sidechainN] = ctip
	}

	if len(m5.Deposits) == 0 || len(m5.Diff) == 0 {
		return M5{}, errors.Errorf("M5 not found")
	}
	return m5, nil
}

func computeM6ID(tx blkdat.Transaction, prevSidechainValue bitcoin.Amount) (types.M6ID, error) {
	input := tx.Input
	output0 := tx.Output[0]
	defer func() {
		tx.Output[0] = output0
		tx.Input = input
	}()

	fee := prevSidechainValue
	for i, o := range tx.Output {
		if fee < o.Amount {
			return types.M6ID{}, errors.Errorf("at output %d fee %d < %d", i, fee, o.Amount)
		}
		fee -= o.Amount
	}

	// Create fee output.
	feeB := make([]byte, 8)
	binary.BigEndian.PutUint64(feeB, fee)
	instrcs := []script.Instruction{
		{Opcode: script.OP_RETURN},
		{Data: feeB},
	}
	tx.Output[0] = blkdat.Output{Script: script.Encode(instrcs)}

	tx.Input = tx.Input[:0]
	m6id := tx.ID()
	slices.Reverse(m6id)
	return m6id, nil
}

func parseM6(tx blkdat.Transaction, txMap map[string]blkdat.Transaction) (M6, error) {
	// Get the sidechainN of this transaction.
	newCtips, err := parseTxOutput(tx)
	if err != nil {
		return M6{}, errors.Wrap(err, "")
	}
	if len(newCtips) != 1 {
		return M6{}, errors.Errorf("%d != 1", len(newCtips))
	}
	sidechainN := slices.Collect(maps.Keys(newCtips))[0]
	ctip := newCtips[sidechainN]
	if ctip.Outpoint.Vout != 0 {
		return M6{}, errors.Errorf("OP_DRIVECHAIN not first output")
	}

	// Get spent treasury utxo.
	if len(tx.Input) != 1 {
		return M6{}, errors.Errorf("%d != 1", len(tx.Input))
	}
	input := tx.Input[0]
	prevTxID := make([]byte, len(input.PrevOut.TxID))
	copy(prevTxID, input.PrevOut.TxID)
	slices.Reverse(prevTxID)
	prevTx, ok := txMap[hex.EncodeToString(prevTxID)]
	if !ok {
		return M6{}, errors.Errorf("input transaction %x not found", input.PrevOut.TxID)
	}
	if int(input.PrevOut.Vout) >= len(prevTx.Output) {
		return M6{}, errors.Errorf("%d >= %d", input.PrevOut.Vout, len(prevTx.Output))
	}
	prevOut := prevTx.Output[input.PrevOut.Vout]
	// Check that previous treasury utxo matches the current one.
	// First, sidechainN should match.
	prevSidechainN, err := treasuryUtxoSidechain(prevOut.Script)
	if err != nil {
		return M6{}, errors.Wrap(err, "")
	}
	if prevSidechainN != sidechainN {
		return M6{}, errors.Errorf("%d != %d", prevSidechainN, sidechainN)
	}
	// Second, treasury value should decrease, since we are withdrawing.
	oldTreasuryValue := prevOut.Amount
	if oldTreasuryValue < ctip.Value {
		return M6{}, errors.Errorf("%d < %d", oldTreasuryValue, ctip.Value)
	}

	m6id, err := computeM6ID(tx, oldTreasuryValue)
	if err != nil {
		return M6{}, errors.Wrap(err, "")
	}

	m6 := M6{
		SidechainN: sidechainN,
		M6:         m6id,
	}
	return m6, nil
}

func parseM8(tx blkdat.Transaction) (M8, error) {
	header := []byte{0x00, 0xbf, 0x00}
	var m8 M8
	wantLen := 1 + len(header) + 1 + len(m8.SidechainBlock) + len(m8.PrevMainBlock)
	if wantLen != 69 {
		log.Fatalf("%d", wantLen)
	}

	spk := tx.Output[0].Script
	if len(spk) != wantLen {
		return M8{}, errors.Errorf("%d != %d", len(spk), wantLen)
	}
	prefix := append([]byte{script.OP_RETURN}, header...)
	if !bytes.HasPrefix(spk, prefix) {
		return M8{}, errors.Errorf("%x", spk[:len(prefix)])
	}
	offset := len(prefix)

	m8.SidechainN = spk[offset]
	offset += 1

	m8.SidechainBlock = BmmCommitment(spk[offset : offset+len(m8.SidechainBlock)])
	offset += len(m8.SidechainBlock)

	m8.PrevMainBlock = bitcoin.BlockHash(spk[offset:])
	return m8, nil
}

func parseTransactions(transactions []blkdat.Transaction, txMap map[string]blkdat.Transaction) ([]Message, error) {
	messages := make([]Message, 0)
	for i, tx := range transactions {
		// Skip coinbase transaction
		if i == 0 {
			continue
		}

		m5, err5 := parseM5(tx, txMap)
		m6, err6 := parseM6(tx, txMap)
		m8, err8 := parseM8(tx)
		switch {
		case err5 != nil && err6 != nil && err8 != nil:
		case err5 == nil && err6 != nil && err8 != nil:
			messages = append(messages, Message{Transaction: i, Msg: m5})
		case err5 != nil && err6 == nil && err8 != nil:
			messages = append(messages, Message{Transaction: i, Msg: m6})
		case err5 != nil && err6 != nil && err8 == nil:
			messages = append(messages, Message{Transaction: i, Msg: m8})
		default:
			// A non coinbase transaction is either a regular Bitcoin transaction, an M5, or an M6.
			// https://github.com/LayerTwo-Labs/bip300_bip301_specifications/blob/537ab3c7587fe835b6ab795ceab0ecfa70242fa4/bip300.md#transaction-validation-rules-specification
			//
			// All non coinbase transactions in the block MUST be valid according to transaction validation rules defined above, if any one of them is invalid, then the whole block is invalid.
			// https://github.com/LayerTwo-Labs/bip300_bip301_specifications/blob/537ab3c7587fe835b6ab795ceab0ecfa70242fa4/bip300.md#block-validation-rules-specification
			return nil, InvalidateBlockError{e: fmt.Sprintf("ambiguous message %x %v %v %v", tx.ID(), err5 == nil, err6 == nil, err8 == nil)}
		}
	}
	return messages, nil
}

func findM7s(ms []Message) (map[SidechainNumber]BmmCommitment, error) {
	// If a mainchain block contains an more than one M7 with the same sidechain slot S, then that block MUST be considered invalid.
	// https://github.com/LayerTwo-Labs/bip300_bip301_specifications/blob/598d642e20d0f1505f5b56aa0a2682e18f87c001/bip301.md#validation-rules
	m7s := make(map[SidechainNumber]Message)
	for _, m := range ms {
		m7, ok := m.Msg.(M7)
		if !ok {
			continue
		}
		if prev, ok := m7s[m7.SidechainN]; ok {
			return nil, InvalidateBlockError{e: fmt.Sprintf("duplicate M7s for sidechain %d at transaction %d and %d", m7.SidechainN, prev.Transaction, m.Transaction)}
		}
		m7s[m7.SidechainN] = m
	}

	res := make(map[SidechainNumber]BmmCommitment, len(m7s))
	for s, m := range m7s {
		res[s] = m.Msg.(M7).SidechainBlock
	}
	return res, nil
}

func checkM8(m8 M8, acceptedBmm map[SidechainNumber]BmmCommitment, prevBlock bitcoin.BlockHash) error {
	// If a mainchain block contains an M8 transaction without the corresponding M7 output, then that block MUST be considered invalid.
	// Corresponding here means that the fields S and H in M8 are equal to the fields S and H in M7, meaning they both refer to the same sidechain block in the same sidechain slot.
	// https://github.com/LayerTwo-Labs/bip300_bip301_specifications/blob/598d642e20d0f1505f5b56aa0a2682e18f87c001/bip301.md#validation-rules
	commitment, ok := acceptedBmm[m8.SidechainN]
	if !ok {
		return InvalidateBlockError{e: fmt.Sprintf("no M7 for sidechain %d", m8.SidechainN)}
	}
	if m8.SidechainBlock != commitment {
		return InvalidateBlockError{e: fmt.Sprintf("M7 M8 sidechain %d hash %x != %x", m8.SidechainN, m8.SidechainBlock, commitment)}
	}

	if m8.PrevMainBlock != prevBlock {
		return errors.Errorf("bmm request expired %x != %x", m8.PrevMainBlock, prevBlock)
	}
	return nil
}

func checkM8s(ms []Message, prevBlock bitcoin.BlockHash) ([]Message, error) {
	m7s, err := findM7s(ms)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}

	const deleteMsg = -1
	for i, m := range ms {
		m8, ok := m.Msg.(M8)
		if !ok {
			continue
		}
		if err := checkM8(m8, m7s, prevBlock); err != nil {
			if _, ok := errors.Cause(err).(InvalidateBlockError); ok {
				return nil, errors.Wrap(err, "")
			}
			ms[i].Transaction = deleteMsg
		}
	}
	ms = slices.DeleteFunc(ms, func(m Message) bool { return m.Transaction == deleteMsg })

	return ms, nil
}

func getMessages(b blkdat.Block, txMap map[string]blkdat.Transaction) ([]Message, error) {
	// Parse coinbase transactions.
	ms := make([]Message, 0)
	cbMs, err := parseCoinbase(b.Transaction[0])
	if err != nil {
		if _, ok := errors.Cause(err).(InvalidateBlockError); ok {
			return nil, errors.Wrap(err, "")
		}
	}
	ms = append(ms, cbMs...)

	// Parse transactions after coinbase.
	tms, err := parseTransactions(b.Transaction, txMap)
	if err != nil {
		if _, ok := errors.Cause(err).(InvalidateBlockError); ok {
			return nil, errors.Wrap(err, "")
		}
	}
	ms = append(ms, tms...)

	ms, err = checkM8s(ms, bitcoin.BlockHash(b.Header.PrevBlock))
	if err != nil {
		if _, ok := errors.Cause(err).(InvalidateBlockError); ok {
			return nil, errors.Wrap(err, "")
		}
	}

	for i := range ms {
		ms[i].Block = b
	}
	return ms, nil
}
