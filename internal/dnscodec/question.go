package dnscodec

import (
	"encoding/binary"
	"fmt"

	"intranet-dns-zone-release-coordinator/internal/zone"
)

// Question is a DNS question (RFC 1035 §4.1.2).
type Question struct {
	Name  zone.Name
	Type  zone.Type
	Class uint16
}

// EncodeQuestion writes a question using compressed names.
func EncodeQuestion(dst []byte, q Question, table map[string]int) []byte {
	dst = EncodeCompressedName(dst, q.Name, table)
	dst = binary.BigEndian.AppendUint16(dst, uint16(q.Type))
	dst = binary.BigEndian.AppendUint16(dst, q.Class)
	return dst
}

// DecodeQuestion reads a question from msg at off.
func DecodeQuestion(msg []byte, off int) (Question, int, error) {
	name, off, err := DecodeName(msg, off)
	if err != nil {
		return Question{}, off, err
	}
	if off+4 > len(msg) {
		return Question{}, off, fmt.Errorf("%w: question type/class truncated at %d", ErrTruncated, off)
	}
	q := Question{
		Name:  name,
		Type:  zone.Type(binary.BigEndian.Uint16(msg[off:])),
		Class: binary.BigEndian.Uint16(msg[off+2:]),
	}
	return q, off + 4, nil
}
