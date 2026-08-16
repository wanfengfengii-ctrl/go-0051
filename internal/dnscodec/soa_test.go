package dnscodec

import (
	"encoding/binary"
	"errors"
	"testing"

	"intranet-dns-zone-release-coordinator/internal/zone"
)

// soaFor builds a representative SOA RDATA value used across the tests.
func soaFor(serial uint32) zone.SOA {
	return zone.SOA{
		MName:   zone.MustNormalizeName("ns1.example.com."),
		RName:   zone.MustNormalizeName("hostmaster.example.com."),
		Serial:  serial,
		Refresh: 3600,
		Retry:   900,
		Expire:  1209600,
		Minimum: 300,
	}
}

// wireSOARR assembles a single SOA RR on the wire from a ready-made RDATA
// byte slice (which may carry extra trailing bytes). The owner is encoded
// uncompressed so the RR is self-contained.
func wireSOARR(owner zone.Name, class uint16, ttl uint32, rdata []byte) []byte {
	var msg []byte
	msg = EncodeName(msg, owner)
	msg = binary.BigEndian.AppendUint16(msg, uint16(zone.TypeSOA))
	msg = binary.BigEndian.AppendUint16(msg, class)
	msg = binary.BigEndian.AppendUint32(msg, ttl)
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(rdata)))
	msg = append(msg, rdata...)
	return msg
}

// TestDecodeSOAValidRoundTrip encodes a valid SOA and decodes it back, checking
// that every field is preserved. This guards against the fix accidentally
// rejecting well-formed records.
func TestDecodeSOAValidRoundTrip(t *testing.T) {
	want := soaFor(20240101)
	owner := zone.MustNormalizeName("example.com.")
	rr := RR{Name: owner, Type: zone.TypeSOA, Class: ClassIN, TTL: 300, RDATA: want}
	wire := EncodeRRUncompressed(nil, rr)

	got, off, err := DecodeRR(wire, 0)
	if err != nil {
		t.Fatalf("DecodeRR valid SOA: %v", err)
	}
	if off != len(wire) {
		t.Errorf("DecodeRR consumed %d bytes, want %d", off, len(wire))
	}
	if got.Name != owner || got.Type != zone.TypeSOA || got.Class != ClassIN || got.TTL != 300 {
		t.Errorf("RR header mismatch: got %+v", got)
	}
	soa, ok := got.RDATA.(zone.SOA)
	if !ok {
		t.Fatalf("RDATA type = %T, want zone.SOA", got.RDATA)
	}
	if !soa.Equal(want) {
		t.Errorf("SOA round-trip mismatch:\n got  %+v\n want %+v", soa, want)
	}
}

// TestDecodeSOAValidCompressedMessage exercises name compression of the SOA
// MName/RName within a full message and verifies the decoder honors pointers
// while still consuming the RDATA exactly.
func TestDecodeSOAValidCompressedMessage(t *testing.T) {
	owner := zone.MustNormalizeName("example.com.")
	soa := soaFor(42)
	m := Message{
		Header:   Header{ID: 1},
		Question: []Question{{Name: owner, Type: zone.TypeSOA, Class: ClassIN}},
		Answers:  []RR{{Name: owner, Type: zone.TypeSOA, Class: ClassIN, TTL: 300, RDATA: soa}},
	}
	wire := EncodeMessage(m)

	decoded, err := DecodeMessage(wire)
	if err != nil {
		t.Fatalf("DecodeMessage compressed SOA: %v", err)
	}
	if len(decoded.Answers) != 1 {
		t.Fatalf("got %d answers, want 1", len(decoded.Answers))
	}
	got, ok := decoded.Answers[0].RDATA.(zone.SOA)
	if !ok {
		t.Fatalf("RDATA type = %T, want zone.SOA", decoded.Answers[0].RDATA)
	}
	if !got.Equal(soa) {
		t.Errorf("compressed SOA mismatch:\n got  %+v\n want %+v", got, soa)
	}
}

// TestDecodeSOATrailingBytesRejected builds a SOA whose RDATA has extra bytes
// after the five 32-bit fixed fields, with RDLENGTH counting them. The decoder
// must reject this as a classifiable error rather than silently accepting it.
func TestDecodeSOATrailingBytesRejected(t *testing.T) {
	soa := soaFor(7)
	// Canonical() yields the exact uncompressed RDATA: MName + RName + 5*uint32.
	rdata := soa.Canonical()
	// Append extra trailing bytes that RDLENGTH will include.
	rdata = append(rdata, 0xDE, 0xAD, 0xBE, 0xEF)
	wire := wireSOARR(zone.MustNormalizeName("example.com."), ClassIN, 300, rdata)

	rr, off, err := DecodeRR(wire, 0)
	if err == nil {
		t.Fatalf("DecodeRR accepted SOA with %d trailing RDATA bytes (off=%d, rr=%+v)",
			4, off, rr)
	}
	if !errors.Is(err, ErrTruncated) {
		t.Errorf("expected ErrTruncated for SOA trailing bytes, got %v", err)
	}
}

// TestDecodeSOAFixedFieldsTruncated ensures the pre-existing truncation guard
// (fewer than 20 bytes for the fixed fields) still fires after the fix.
func TestDecodeSOAFixedFieldsTruncated(t *testing.T) {
	soa := soaFor(7)
	rdata := soa.Canonical()
	// Drop the last 4 bytes so only 16 of the 20 fixed-field bytes remain.
	rdata = rdata[:len(rdata)-4]
	wire := wireSOARR(zone.MustNormalizeName("example.com."), ClassIN, 300, rdata)

	if _, _, err := DecodeRR(wire, 0); err == nil {
		t.Fatal("DecodeRR accepted SOA with truncated fixed fields")
	} else if !errors.Is(err, ErrTruncated) {
		t.Errorf("expected ErrTruncated for truncated SOA fixed fields, got %v", err)
	}
}

// TestDecodeMessageRejectsSOATrailingBytes verifies that a malformed SOA in the
// answer section causes DecodeMessage to surface a classifiable error (the RR
// error must propagate to the caller rather than being swallowed).
func TestDecodeMessageRejectsSOATrailingBytes(t *testing.T) {
	soa := soaFor(7)
	rdata := soa.Canonical()
	rdata = append(rdata, 0x01, 0x02, 0x03) // trailing bytes counted by RDLENGTH
	rr := wireSOARR(zone.MustNormalizeName("example.com."), ClassIN, 300, rdata)

	// Assemble a full message: header (ANCount=1) + the malformed SOA RR.
	var msg []byte
	msg = EncodeHeader(msg, Header{ANCount: 1})
	msg = append(msg, rr...)

	if _, err := DecodeMessage(msg); err == nil {
		t.Fatal("DecodeMessage accepted a message with a malformed SOA")
	} else if !errors.Is(err, ErrTruncated) {
		t.Errorf("expected ErrTruncated to propagate from DecodeMessage, got %v", err)
	}
}

// TestDecodeOtherRRTypesUnaffected is a regression guard confirming the SOA
// boundary fix does not perturb decoding of other supported RR types.
func TestDecodeOtherRRTypesUnaffected(t *testing.T) {
	owner := zone.MustNormalizeName("example.com.")
	cases := []RR{
		{Name: owner, Type: zone.TypeA, Class: ClassIN, TTL: 300, RDATA: zone.A{IP: [4]byte{10, 0, 0, 1}}},
		{Name: owner, Type: zone.TypeAAAA, Class: ClassIN, TTL: 300, RDATA: zone.AAAA{IP: [16]byte{0: 0x20, 1: 0x01, 12: 0xff}}},
		{Name: owner, Type: zone.TypeNS, Class: ClassIN, TTL: 300, RDATA: zone.NS{NSDName: zone.MustNormalizeName("ns1.example.com.")}},
		{Name: owner, Type: zone.TypeCNAME, Class: ClassIN, TTL: 300, RDATA: zone.CNAME{Target: zone.MustNormalizeName("target.example.com.")}},
		{Name: owner, Type: zone.TypeTXT, Class: ClassIN, TTL: 300, RDATA: zone.TXT{Texts: []string{"hello", "world"}}},
	}
	for _, c := range cases {
		wire := EncodeRRUncompressed(nil, c)
		got, off, err := DecodeRR(wire, 0)
		if err != nil {
			t.Errorf("DecodeRR(%s): %v", c.Type, err)
			continue
		}
		if off != len(wire) {
			t.Errorf("DecodeRR(%s) consumed %d, want %d", c.Type, off, len(wire))
		}
		if !got.RDATA.Equal(c.RDATA) {
			t.Errorf("DecodeRR(%s) RDATA mismatch:\n got  %+v\n want %+v", c.Type, got.RDATA, c.RDATA)
		}
	}
}
