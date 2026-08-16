package dnscodec

import (
	"encoding/binary"
	"fmt"
	"strings"

	"intranet-dns-zone-release-coordinator/internal/zone"
)

// pointerMask distinguishes a compression pointer (0xC0) from a label (0x00)
// and the reserved label types (0x40, 0x80).
const (
	labelMask    = 0xC0
	labelRegular = 0x00
	labelPointer = 0xC0
)

// EncodeName writes an uncompressed (canonical) name to dst. Uncompressed form
// is always used for RDATA and AXFR output so that records are self-describing
// and canonical (RFC 4034 §6.2). Compression is only applied at the
// message-body level by EncodeMessage via a compression table.
func EncodeName(dst []byte, name zone.Name) []byte {
	if name.IsRoot() {
		return append(dst, 0)
	}
	for _, l := range name.Labels() {
		if len(l) > maxLabelLength {
			l = l[:maxLabelLength]
		}
		dst = append(dst, byte(len(l)))
		dst = append(dst, l...)
	}
	return append(dst, 0)
}

// EncodeCompressedName writes name to dst, emitting a compression pointer when
// a suffix of the name was already written at a known offset. The compression
// table maps a canonical name suffix to the byte offset of its encoding in the
// message being built. Offsets must be < 0x4000 (14 bits).
func EncodeCompressedName(dst []byte, name zone.Name, table map[string]int) []byte {
	if name.IsRoot() {
		return append(dst, 0)
	}
	cur := name
	for !cur.IsRoot() {
		key := string(cur)
		if off, ok := table[key]; ok && off < 0x4000 {
			ptr := uint16(labelPointer<<8) | uint16(off)
			dst = binary.BigEndian.AppendUint16(dst, ptr)
			return dst
		}
		// Record the offset of this suffix before emitting the next label.
		table[key] = len(dst)
		labels := cur.Labels()
		head := labels[0]
		if len(head) > maxLabelLength {
			head = head[:maxLabelLength]
		}
		dst = append(dst, byte(len(head)))
		dst = append(dst, head...)
		rest := strings.Join(labels[1:], ".")
		if rest == "" {
			cur = zone.Name(".")
		} else {
			cur = zone.Name(rest + ".")
		}
	}
	return append(dst, 0)
}

// DecodeName decodes a (possibly compressed) name starting at off within msg.
// It enforces packet boundaries, bounds pointer jumps, and rejects cycles and
// reserved label types, returning a stable ErrCompressionPointer or
// ErrTruncated as appropriate.
//
// The returned offset is the position in msg immediately after the name as it
// appears inline (i.e. following the terminal zero or pointer, not following
// the data the pointer references).
func DecodeName(msg []byte, off int) (zone.Name, int, error) {
	if off >= len(msg) {
		return "", off, fmt.Errorf("%w: name start at %d past end", ErrTruncated, off)
	}
	var labels []string
	pos := off
	jumps := 0
	next := -1 // offset after the inline name (set on first pointer)
	visited := map[int]struct{}{}

	for {
		if pos >= len(msg) {
			return "", off, fmt.Errorf("%w: name truncated at %d", ErrTruncated, pos)
		}
		b := msg[pos]
		switch b & labelMask {
		case labelRegular:
			if b == 0 {
				pos++
				if next < 0 {
					next = pos
				}
				return assembleName(labels), next, nil
			}
			if int(b) > len(msg)-pos-1 {
				return "", off, fmt.Errorf("%w: label length %d exceeds packet at %d", ErrTruncated, b, pos)
			}
			labels = append(labels, string(msg[pos+1:pos+1+int(b)]))
			pos += 1 + int(b)
		case labelPointer:
			if pos+1 >= len(msg) {
				return "", off, fmt.Errorf("%w: pointer second octet missing at %d", ErrTruncated, pos)
			}
			ptr := (uint16(b&0x3F) << 8) | uint16(msg[pos+1])
			if int(ptr) >= len(msg) {
				return "", off, fmt.Errorf("%w: pointer offset %d out of bounds", ErrCompressionPointer, ptr)
			}
			if _, seen := visited[int(ptr)]; seen {
				return "", off, fmt.Errorf("%w: cyclic pointer to %d", ErrCompressionPointer, ptr)
			}
			visited[int(ptr)] = struct{}{}
			if next < 0 {
				next = pos + 2
			}
			pos = int(ptr)
			jumps++
			if jumps > maxPointerJumps {
				return "", off, fmt.Errorf("%w: too many pointer jumps", ErrCompressionPointer)
			}
		default:
			// 0x40 or 0x80: reserved label types (binary labels, etc.). The
			// coordinator does not support them and classifies them as
			// compression/name errors per the acceptance contract.
			return "", off, fmt.Errorf("%w: reserved label type %#02x at %d", ErrCompressionPointer, b, pos)
		}
	}
}

func assembleName(labels []string) zone.Name {
	if len(labels) == 0 {
		return zone.Name(".")
	}
	return zone.Name(strings.ToLower(strings.Join(labels, ".") + "."))
}

// SkipName advances past a name (honoring compression) without materializing
// it, returning the offset after the inline name.
func SkipName(msg []byte, off int) (int, error) {
	_, next, err := DecodeName(msg, off)
	return next, err
}
