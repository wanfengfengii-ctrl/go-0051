package dnscodec

import (
	"encoding/binary"
	"errors"
	"testing"

	"intranet-dns-zone-release-coordinator/internal/zone"
)

func TestDecodeSOARDataLengthValidation(t *testing.T) {
	soa := zone.SOA{
		MName:   zone.MustNormalizeName("ns1.example.com."),
		RName:   zone.MustNormalizeName("hostmaster.example.com."),
		Serial:  2026081601,
		Refresh: 3600,
		Retry:   900,
		Expire:  1209600,
		Minimum: 300,
	}
	rr := RR{
		Name:  zone.MustNormalizeName("example.com."),
		Type:  zone.TypeSOA,
		Class: ClassIN,
		TTL:   300,
		RDATA: soa,
	}

	addTrailingRDATA := func(t *testing.T, wire []byte, rrOffset int, trailing []byte) []byte {
		t.Helper()
		malformed := append(append([]byte(nil), wire...), trailing...)
		_, fixedFields, err := DecodeName(malformed, rrOffset)
		if err != nil {
			t.Fatalf("locate RR fixed fields: %v", err)
		}
		rdlengthOffset := fixedFields + 8
		rdlength := binary.BigEndian.Uint16(malformed[rdlengthOffset:])
		binary.BigEndian.PutUint16(malformed[rdlengthOffset:], rdlength+uint16(len(trailing)))
		return malformed
	}

	t.Run("valid compressed message", func(t *testing.T) {
		wire := EncodeMessage(Message{Answers: []RR{rr}})
		got, err := DecodeMessage(wire)
		if err != nil {
			t.Fatalf("DecodeMessage(valid SOA): %v", err)
		}
		if len(got.Answers) != 1 || !got.Answers[0].RDATA.Equal(soa) {
			t.Fatalf("decoded SOA = %#v, want %#v", got.Answers, soa)
		}
	})

	t.Run("record rejects trailing bytes", func(t *testing.T) {
		wire := EncodeRRUncompressed(nil, rr)
		for _, trailing := range [][]byte{{0xff}, {0xde, 0xad, 0xbe}} {
			malformed := addTrailingRDATA(t, wire, 0, trailing)
			if _, _, err := DecodeRR(malformed, 0); !errors.Is(err, ErrTruncated) {
				t.Errorf("DecodeRR with %d trailing bytes error = %v, want ErrTruncated", len(trailing), err)
			}
		}
	})

	t.Run("message propagates RDATA error", func(t *testing.T) {
		const rrOffset = 12
		wire := EncodeMessage(Message{Answers: []RR{rr}})
		malformed := addTrailingRDATA(t, wire, rrOffset, []byte{0xff})
		if _, err := DecodeMessage(malformed); !errors.Is(err, ErrTruncated) {
			t.Fatalf("DecodeMessage error = %v, want ErrTruncated", err)
		}
	})
}
