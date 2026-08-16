package dnscodec

import (
	"encoding/binary"
	"fmt"

	"intranet-dns-zone-release-coordinator/internal/zone"
)

// Message is a decoded DNS message: header, question section and the three RR
// sections. The update section maps to NS (per RFC 2136).
type Message struct {
	Header     Header
	Question   []Question
	Answers    []RR
	Authority  []RR // UPDATE zone/updates live here
	Additional []RR
}

// EncodeMessage assembles a full DNS message. Names in the question and RR
// sections share one compression table so suffixes compress against earlier
// occurrences.
func EncodeMessage(m Message) []byte {
	table := map[string]int{}
	var dst []byte
	m.Header.QDCount = uint16(len(m.Question))
	m.Header.ANCount = uint16(len(m.Answers))
	m.Header.NSCount = uint16(len(m.Authority))
	m.Header.ARCount = uint16(len(m.Additional))
	dst = EncodeHeader(dst, m.Header)
	for _, q := range m.Question {
		dst = EncodeQuestion(dst, q, table)
	}
	for _, rr := range m.Answers {
		dst = EncodeRR(dst, rr, table)
	}
	for _, rr := range m.Authority {
		dst = EncodeRR(dst, rr, table)
	}
	for _, rr := range m.Additional {
		dst = EncodeRR(dst, rr, table)
	}
	return dst
}

// DecodeMessage parses a full DNS message, enforcing section counts and packet
// boundaries. It consumes exactly len(msg) bytes conceptually; trailing garbage
// is rejected as a truncation/invalid condition.
func DecodeMessage(msg []byte) (Message, error) {
	h, off, err := DecodeHeader(msg, 0)
	if err != nil {
		return Message{}, err
	}
	m := Message{Header: h}
	for i := 0; i < int(h.QDCount); i++ {
		q, no, err := DecodeQuestion(msg, off)
		if err != nil {
			return m, err
		}
		m.Question = append(m.Question, q)
		off = no
	}
	if m.Question, off, err = decodeRRs(msg, off, int(h.ANCount), m.Question, &m.Answers); err != nil {
		return m, err
	}
	if m.Question, off, err = decodeRRs(msg, off, int(h.NSCount), m.Question, &m.Authority); err != nil {
		return m, err
	}
	if m.Question, off, err = decodeRRs(msg, off, int(h.ARCount), m.Question, &m.Additional); err != nil {
		return m, err
	}
	if off != len(msg) {
		return m, fmt.Errorf("%w: %d trailing bytes", ErrTruncated, len(msg)-off)
	}
	return m, nil
}

// decodeRRs reads count RRs into dst. The qs argument is the question section
// decoded so far; it is threaded through and returned unchanged so that
// DecodeMessage preserves m.Question across the answer, authority and
// additional sections instead of wiping it (which left ParseUpdate unable to
// recover the UPDATE zone section after decoding).
func decodeRRs(msg []byte, off, count int, qs []Question, dst *[]RR) ([]Question, int, error) {
	for i := 0; i < count; i++ {
		rr, no, err := DecodeRR(msg, off)
		if err != nil {
			return qs, off, err
		}
		*dst = append(*dst, rr)
		off = no
	}
	return qs, off, nil
}

// ReadTCPFrame reads a single DNS-over-TCP message: a 2-byte big-endian length
// prefix followed by that many bytes. A short or absent length prefix and a
// short payload are both reported as ErrTruncated. The returned message slice
// aliases the buffer.
func ReadTCPFrame(r interface{ Read(p []byte) (int, error) }) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := readFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("%w: tcp length prefix: %v", ErrTruncated, err)
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := readFull(r, buf); err != nil {
		return nil, fmt.Errorf("%w: tcp payload: %v", ErrTruncated, err)
	}
	return buf, nil
}

// WriteTCPFrame writes a 2-byte length-prefixed DNS-over-TCP frame, looping on
// short writes until the full frame is written or an error occurs.
func WriteTCPFrame(w interface{ Write(p []byte) (int, error) }, msg []byte) error {
	if len(msg) > 0xFFFF {
		return fmt.Errorf("%w: message too large for TCP frame", ErrInvalidMessage)
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(msg)))
	if err := writeFull(w, lenBuf[:]); err != nil {
		return err
	}
	return writeFull(w, msg)
}

func readFull(r interface{ Read(p []byte) (int, error) }, dst []byte) (int, error) {
	total := 0
	for total < len(dst) {
		n, err := r.Read(dst[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, fmt.Errorf("short read")
		}
	}
	return total, nil
}

func writeFull(w interface{ Write(p []byte) (int, error) }, src []byte) error {
	total := 0
	for total < len(src) {
		n, err := w.Write(src[total:])
		total += n
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("short write")
		}
	}
	return nil
}

// RRFromRecord converts a zone.Record to an RR suitable for encoding.
func RRFromRecord(r zone.Record, class uint16) RR {
	return RR{Name: r.Name, Type: r.Type, Class: class, TTL: r.TTL, RDATA: r.RDATA}
}

// RecordToRRs converts the records of a snapshot section into RRs.
func RecordToRRs(recs []zone.Record, class uint16) []RR {
	out := make([]RR, 0, len(recs))
	for _, r := range recs {
		out = append(out, RRFromRecord(r, class))
	}
	return out
}
