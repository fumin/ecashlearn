package script

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

const (
	OP_0         byte = 0x00
	OP_PUSHDATA1 byte = 0x4c
	OP_PUSHDATA2 byte = 0x4d
	OP_PUSHDATA4 byte = 0x4e
	OP_1         byte = 0x51
	OP_TRUE      byte = OP_1
	OP_2         byte = 0x52
	OP_3         byte = 0x53
	OP_4         byte = 0x54
	OP_5         byte = 0x55
	OP_6         byte = 0x56
	OP_7         byte = 0x57
	OP_8         byte = 0x58
	OP_9         byte = 0x59
	OP_10        byte = 0x5a
	OP_11        byte = 0x5b
	OP_12        byte = 0x5c
	OP_13        byte = 0x5d
	OP_14        byte = 0x5e
	OP_15        byte = 0x5f
	OP_16        byte = 0x60

	OP_RETURN byte = 0x6a

	OP_DUP byte = 0x76

	OP_EQUAL       byte = 0x87
	OP_EQUALVERIFY byte = 0x88

	OP_HASH160  byte = 0xa9
	OP_CHECKSIG byte = 0xac

	OP_NOP5 byte = 0xb4

	OP_INVALIDOPCODE byte = 0xff
)

var (
	invalidInstruction = Instruction{Opcode: OP_INVALIDOPCODE}
)

type Instruction struct {
	Opcode byte
	Data   []byte
}

func Encode(instrcs []Instruction) []byte {
	b := make([]byte, 0)
	for _, ins := range instrcs {
		switch len(ins.Data) {
		case 0:
			b = append(b, ins.Opcode)
		default:
			b = appendSize(b, len(ins.Data))
			b = append(b, ins.Data...)
		}
	}
	return b
}

func appendSize(b []byte, size int) []byte {
	switch {
	case size < int(OP_PUSHDATA1):
		b = append(b, byte(size))
	case size <= 0xff:
		b = append(b, OP_PUSHDATA1)
		b = append(b, byte(size))
	case size <= 0xffff:
		b = append(b, OP_PUSHDATA2)
		b = binary.LittleEndian.AppendUint16(b, uint16(size))
	case size < 0xffffffff:
		b = append(b, OP_PUSHDATA4)
		b = binary.LittleEndian.AppendUint32(b, uint32(size))
	default:
		panic("data too large")
	}
	return b
}

func Decode(data []byte) ([]Instruction, error) {
	p := &parser{}
	instrcs := make([]Instruction, 0)
	for p.offset < len(data) {
		ins, err := p.readInstruction(data)
		if err != nil {
			return nil, errors.Wrap(err, "")
		}
		instrcs = append(instrcs, ins)
	}
	return instrcs, nil
}

type parser struct {
	offset int
}

func (p *parser) readInstruction(data []byte) (Instruction, error) {
	if err := p.withinBounds(data, 1); err != nil {
		return invalidInstruction, errors.Wrap(err, "")
	}
	opcode := data[p.offset]
	p.offset++

	size := -1
	switch {
	case opcode < OP_PUSHDATA1:
		size = int(opcode)
	case opcode == OP_PUSHDATA1:
		if err := p.withinBounds(data, 1); err != nil {
			return invalidInstruction, errors.Wrap(err, "")
		}
		size = int(data[p.offset])
		p.offset++
	case opcode == OP_PUSHDATA2:
		if err := p.withinBounds(data, 2); err != nil {
			return invalidInstruction, errors.Wrap(err, "")
		}
		d := data[p.offset : p.offset+2]
		size = int(binary.LittleEndian.Uint16(d))
		p.offset += 2
	case opcode == OP_PUSHDATA4:
		if err := p.withinBounds(data, 4); err != nil {
			return invalidInstruction, errors.Wrap(err, "")
		}
		d := data[p.offset : p.offset+4]
		size = int(binary.LittleEndian.Uint16(d))
		p.offset += 4
	}
	if size == -1 {
		return Instruction{Opcode: opcode}, nil
	}

	if err := p.withinBounds(data, size); err != nil {
		return invalidInstruction, errors.Wrap(err, "")
	}
	ins := Instruction{Data: data[p.offset : p.offset+size]}
	p.offset += size
	return ins, nil
}

func (p *parser) withinBounds(data []byte, size int) error {
	if p.offset+size > len(data) {
		return errors.Errorf("%d+%d > %d", p.offset, size, len(data))
	}
	return nil
}
