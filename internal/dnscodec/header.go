package dnscodec

import (
	"encoding/binary"
	"fmt"
)

// Header is the 12-octet DNS message header (RFC 1035 §4.1.1).
type Header struct {
	ID       uint16
	Flags    uint16 // QR(1)|Opcode(4)|AA(1)|TC(1)|RD(1)|RA(1)|Z(3)|RCODE(4)
	QDCount  uint16
	ANCount  uint16
	NSCount  uint16
	ARCount  uint16
}

// Flag bit masks and field positions.
const (
	flagQR     uint16 = 1 << 15
	flagOpcode uint16 = 0x7800 // bits 11-14
	flagAA     uint16 = 1 << 10
	flagTC     uint16 = 1 << 9
	flagRD     uint16 = 1 << 8
	flagRA     uint16 = 1 << 7
	flagZ      uint16 = 7 << 4
	flagRcode  uint16 = 0x000F
	opcodeShift       = 11
)

// QR reports the query/response bit.
func (h Header) QR() bool { return h.Flags&flagQR != 0 }

// SetQR sets the query/response bit.
func (h *Header) SetQR(v bool) {
	if v {
		h.Flags |= flagQR
	} else {
		h.Flags &^= flagQR
	}
}

// Opcode returns the 4-bit opcode.
func (h Header) Opcode() uint16 { return (h.Flags & flagOpcode) >> opcodeShift }

// SetOpcode sets the 4-bit opcode.
func (h *Header) SetOpcode(op uint16) {
	h.Flags = (h.Flags &^ flagOpcode) | ((op & 0x0F) << opcodeShift)
}

// AA reports the authoritative-answer bit.
func (h Header) AA() bool { return h.Flags&flagAA != 0 }

// SetAA sets the authoritative-answer bit.
func (h *Header) SetAA(v bool) {
	if v {
		h.Flags |= flagAA
	} else {
		h.Flags &^= flagAA
	}
}

// TC reports the truncation bit.
func (h Header) TC() bool { return h.Flags&flagTC != 0 }

// RCODE returns the 4-bit reply code.
func (h Header) RCODE() uint16 { return h.Flags & flagRcode }

// SetRCODE sets the 4-bit reply code.
func (h *Header) SetRCODE(rc uint16) {
	h.Flags = (h.Flags &^ flagRcode) | (rc & flagRcode)
}

// EncodeHeader writes the 12-octet header to dst and returns the extended slice.
func EncodeHeader(dst []byte, h Header) []byte {
	dst = binary.BigEndian.AppendUint16(dst, h.ID)
	dst = binary.BigEndian.AppendUint16(dst, h.Flags)
	dst = binary.BigEndian.AppendUint16(dst, h.QDCount)
	dst = binary.BigEndian.AppendUint16(dst, h.ANCount)
	dst = binary.BigEndian.AppendUint16(dst, h.NSCount)
	dst = binary.BigEndian.AppendUint16(dst, h.ARCount)
	return dst
}

// DecodeHeader parses a 12-octet header from msg starting at off. It returns
// the header and the new offset, or ErrTruncated if the header is incomplete.
func DecodeHeader(msg []byte, off int) (Header, int, error) {
	if off+12 > len(msg) {
		return Header{}, off, fmt.Errorf("%w: incomplete header at %d", ErrTruncated, off)
	}
	h := Header{
		ID:      binary.BigEndian.Uint16(msg[off:]),
		Flags:   binary.BigEndian.Uint16(msg[off+2:]),
		QDCount: binary.BigEndian.Uint16(msg[off+4:]),
		ANCount: binary.BigEndian.Uint16(msg[off+6:]),
		NSCount: binary.BigEndian.Uint16(msg[off+8:]),
		ARCount: binary.BigEndian.Uint16(msg[off+10:]),
	}
	return h, off + 12, nil
}
