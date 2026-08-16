package dnscodec

import (
	"bytes"
	"errors"
	"testing"

	"intranet-dns-zone-release-coordinator/internal/zone"
)

func mustName(t *testing.T, s string) zone.Name {
	t.Helper()
	n, err := zone.NormalizeName(s)
	if err != nil {
		t.Fatalf("NormalizeName(%q): %v", s, err)
	}
	return n
}

func TestDecodeMessagePreservesQuestions_PureQuery(t *testing.T) {
	q := Question{Name: mustName(t, "www.example.com."), Type: zone.TypeA, Class: ClassIN}
	m := Message{
		Header:   Header{ID: 0x1234, Flags: 0x0100}, // RD set, plain query
		Question: []Question{q},
	}
	wire := EncodeMessage(m)

	dec, err := DecodeMessage(wire)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if dec.Header.QDCount != 1 {
		t.Errorf("QDCount = %d, want 1", dec.Header.QDCount)
	}
	if len(dec.Question) != 1 {
		t.Fatalf("len(Question) = %d, want 1", len(dec.Question))
	}
	if dec.Question[0].Name != q.Name || dec.Question[0].Type != q.Type || dec.Question[0].Class != q.Class {
		t.Errorf("Question = %+v, want %+v", dec.Question[0], q)
	}
	if len(dec.Answers) != 0 || len(dec.Authority) != 0 || len(dec.Additional) != 0 {
		t.Errorf("RR sections not empty: ans=%d auth=%d add=%d", len(dec.Answers), len(dec.Authority), len(dec.Additional))
	}
}

func TestDecodeMessagePreservesQuestions_WithRRs(t *testing.T) {
	q := Question{Name: mustName(t, "www.example.com."), Type: zone.TypeA, Class: ClassIN}
	ans := RR{
		Name:  mustName(t, "www.example.com."),
		Type:  zone.TypeA,
		Class: ClassIN,
		TTL:   300,
		RDATA: zone.A{IP: [4]byte{10, 0, 0, 1}},
	}
	auth := RR{
		Name:  mustName(t, "example.com."),
		Type:  zone.TypeNS,
		Class: ClassIN,
		TTL:   3600,
		RDATA: zone.NS{NSDName: mustName(t, "ns1.example.com.")},
	}
	m := Message{
		Header:    Header{ID: 0x5678, Flags: 0x8180}, // QR|AA|RD|RA response
		Question:  []Question{q},
		Answers:   []RR{ans},
		Authority: []RR{auth},
	}
	wire := EncodeMessage(m)
	dec, err := DecodeMessage(wire)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}

	if dec.Header.QDCount != 1 || dec.Header.ANCount != 1 || dec.Header.NSCount != 1 || dec.Header.ARCount != 0 {
		t.Errorf("counts = qd=%d an=%d ns=%d ar=%d, want 1,1,1,0",
			dec.Header.QDCount, dec.Header.ANCount, dec.Header.NSCount, dec.Header.ARCount)
	}
	if len(dec.Question) != 1 {
		t.Fatalf("len(Question) = %d, want 1", len(dec.Question))
	}
	if dec.Question[0] != q {
		t.Errorf("Question[0] = %+v, want %+v", dec.Question[0], q)
	}
	if len(dec.Answers) != 1 {
		t.Fatalf("len(Answers) = %d, want 1", len(dec.Answers))
	}
	if !dec.Answers[0].RDATA.Equal(ans.RDATA) || dec.Answers[0].Name != ans.Name || dec.Answers[0].Type != ans.Type {
		t.Errorf("Answer = %+v, want %+v", dec.Answers[0], ans)
	}
	if len(dec.Authority) != 1 {
		t.Fatalf("len(Authority) = %d, want 1", len(dec.Authority))
	}
	if !dec.Authority[0].RDATA.Equal(auth.RDATA) || dec.Authority[0].Name != auth.Name {
		t.Errorf("Authority = %+v, want %+v", dec.Authority[0], auth)
	}
}

func TestDecodeMessageQuestionRoundTripMultiple(t *testing.T) {
	// Multiple questions round-trip and survive the presence of an Additional RR.
	qs := []Question{
		{Name: mustName(t, "a.example.com."), Type: zone.TypeA, Class: ClassIN},
		{Name: mustName(t, "b.example.com."), Type: zone.TypeAAAA, Class: ClassIN},
	}
	add := RR{
		Name:  mustName(t, "a.example.com."),
		Type:  zone.TypeA,
		Class: ClassIN,
		TTL:   60,
		RDATA: zone.A{IP: [4]byte{192, 0, 2, 5}},
	}
	m := Message{
		Header:     Header{ID: 1},
		Question:   qs,
		Additional: []RR{add},
	}
	wire := EncodeMessage(m)
	dec, err := DecodeMessage(wire)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if len(dec.Question) != 2 {
		t.Fatalf("len(Question) = %d, want 2", len(dec.Question))
	}
	for i, q := range qs {
		if dec.Question[i] != q {
			t.Errorf("Question[%d] = %+v, want %+v", i, dec.Question[i], q)
		}
	}
	if len(dec.Additional) != 1 || !dec.Additional[0].RDATA.Equal(add.RDATA) {
		t.Errorf("Additional = %+v, want one %v", dec.Additional, add)
	}
}

func TestDecodeMessageRejectsTrailingData(t *testing.T) {
	q := Question{Name: mustName(t, "www.example.com."), Type: zone.TypeA, Class: ClassIN}
	wire := EncodeMessage(Message{Header: Header{ID: 1}, Question: []Question{q}})
	wire = append(wire, 0xDE, 0xAD, 0xBE, 0xEF) // trailing bytes
	_, err := DecodeMessage(wire)
	if !errors.Is(err, ErrTruncated) {
		t.Errorf("expected ErrTruncated for trailing data, got %v", err)
	}
}

func TestEncodeDecodeMessageByteIdenticalRoundTrip(t *testing.T) {
	// The fix must not alter encoding: a re-encode of the decoded message must
	// produce byte-identical wire form for an RR-bearing message.
	q := Question{Name: mustName(t, "www.example.com."), Type: zone.TypeA, Class: ClassIN}
	ans := RR{
		Name: mustName(t, "www.example.com."), Type: zone.TypeA, Class: ClassIN, TTL: 300,
		RDATA: zone.A{IP: [4]byte{10, 0, 0, 1}},
	}
	m := Message{Header: Header{ID: 0xABCD}, Question: []Question{q}, Answers: []RR{ans}}
	wire := EncodeMessage(m)
	dec, err := DecodeMessage(wire)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	re := EncodeMessage(dec)
	if !bytes.Equal(wire, re) {
		t.Errorf("round-trip wire differs:\n got %x\n want %x", re, wire)
	}
}
