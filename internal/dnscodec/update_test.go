package dnscodec

import (
	"testing"

	"intranet-dns-zone-release-coordinator/internal/zone"
)

func TestBuildUpdateRoundTrip(t *testing.T) {
	const id uint16 = 0x2136
	key := zone.ZoneKey{
		View: "internal",
		Name: zone.MustNormalizeName("example.com."),
	}
	meta := UpdateMeta{
		View:             string(key.View),
		OpID:             "update-42",
		ExpectedRevision: 17,
		BaseActiveSerial: 2026081601,
	}
	add := zone.UpdateOp{
		Kind:  zone.OpAdd,
		Name:  zone.MustNormalizeName("www.example.com."),
		Type:  zone.TypeA,
		TTL:   300,
		RDATA: zone.A{IP: [4]byte{192, 0, 2, 10}},
	}

	for _, tc := range []struct {
		name string
		ops  []zone.UpdateOp
	}{
		{name: "empty"},
		{name: "with operation", ops: []zone.UpdateOp{add}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := DecodeMessage(BuildUpdate(id, key, tc.ops, meta))
			if err != nil {
				t.Fatalf("DecodeMessage: %v", err)
			}
			if msg.Header.ID != id {
				t.Errorf("transaction ID = %#x, want %#x", msg.Header.ID, id)
			}
			if got := msg.Header.Opcode(); got != OpUpdate {
				t.Fatalf("opcode = %d, want UPDATE (%d)", got, OpUpdate)
			}

			gotKey, gotOps, gotMeta, err := ParseUpdate(msg)
			if err != nil {
				t.Fatalf("ParseUpdate: %v", err)
			}
			if gotKey != key {
				t.Errorf("zone key = %+v, want %+v", gotKey, key)
			}
			if gotMeta == nil || *gotMeta != meta {
				t.Errorf("update metadata = %+v, want %+v", gotMeta, meta)
			}
			if len(gotOps) != len(tc.ops) {
				t.Fatalf("operations = %d, want %d", len(gotOps), len(tc.ops))
			}
			if len(tc.ops) == 1 {
				got := gotOps[0]
				if got.Kind != add.Kind || got.Name != add.Name || got.Type != add.Type || got.TTL != add.TTL {
					t.Errorf("operation = %+v, want fields from %+v", got, add)
				}
				if got.RDATA == nil || !got.RDATA.Equal(add.RDATA) {
					t.Errorf("operation RDATA = %+v, want %+v", got.RDATA, add.RDATA)
				}
			}
		})
	}

	query, err := DecodeMessage(EncodeMessage(Message{Header: Header{ID: id}}))
	if err != nil {
		t.Fatalf("DecodeMessage(query): %v", err)
	}
	if got := query.Header.Opcode(); got != OpQuery {
		t.Errorf("ordinary query opcode = %d, want QUERY (%d)", got, OpQuery)
	}
}
