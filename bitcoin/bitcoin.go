package bitcoin

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/fumin/ecashlearn/crypto"
)

type Transaction struct {
	Version  uint32
	LockTime uint32
	Input    []TxIn
	Output   []TxOut
}

func (t Transaction) ID() []byte {
	id := make([]byte, 0)
	id = binary.LittleEndian.AppendUint32(id, t.Version)

	id = AppendVarInt(id, len(t.Input))
	for _, inp := range t.Input {
		id = append(id, inp.PrevOut.TxID[:]...)
		id = binary.LittleEndian.AppendUint32(id, inp.PrevOut.Vout)
		id = AppendVarInt(id, len(inp.Script))
		id = append(id, inp.Script...)
		id = binary.LittleEndian.AppendUint32(id, inp.Sequence)
	}

	id = AppendVarInt(id, len(t.Output))
	for _, out := range t.Output {
		id = binary.LittleEndian.AppendUint64(id, out.Amount)
		id = AppendVarInt(id, len(out.Script))
		id = append(id, out.Script...)
	}
	id = binary.LittleEndian.AppendUint32(id, t.LockTime)

	id = crypto.DoubleSha256(id)
	return id
}

func DecodeVarInt(data []byte) (int, int) {
	b := data[0]
	switch b {
	case 0xfd:
		d := data[1 : 1+2]
		return int(binary.LittleEndian.Uint16(d)), 3
	case 0xfe:
		d := data[1 : 1+4]
		return int(binary.LittleEndian.Uint32(d)), 5
	case 0xff:
		d := data[1 : 1+8]
		return int(binary.LittleEndian.Uint64(d)), 9
	default:
		return int(b), 1
	}
}

func AppendVarInt(b []byte, i int) []byte {
	switch {
	case i < 0xfd:
		b = append(b, byte(i))
	case i <= 0xffff:
		b = append(b, 0xfd)
		b = binary.LittleEndian.AppendUint16(b, uint16(i))
	case i <= 0xffffffff:
		b = append(b, 0xfe)
		b = binary.LittleEndian.AppendUint32(b, uint32(i))
	default:
		b = append(b, 0xff)
		b = binary.LittleEndian.AppendUint64(b, uint64(i))
	}
	return b
}

type TxIn struct {
	PrevOut  Outpoint
	Script   []byte
	Sequence uint32
	Witness  Witness
}

type Witness struct {
	Content         []byte
	WitnessElements uint64
	IndicesStart    uint64
}

type TxOut struct {
	Amount Amount
	Script []byte
}

type Outpoint struct {
	TxID []byte
	Vout uint32
}

type BlockHash = [sha256.Size]byte

type Amount = uint64

func BtcToSats(btc float64) Amount {
	return Amount(btc * 1e8)
}
