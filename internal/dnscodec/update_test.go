package dnscodec

import (
	"testing"

	"intranet-dns-zone-release-coordinator/internal/zone"
)

// mustName normalizes a textual name or fails the test.
func mustName(t *testing.T, s string) zone.Name {
	t.Helper()
	n, err := zone.NormalizeName(s)
	if err != nil {
		t.Fatalf("NormalizeName(%q): %v", s, err)
	}
	return n
}

// TestBuildUpdateHeaderOpcode verifies that BuildUpdate stamps the RFC 2136
// UPDATE opcode (5) into the message header, rather than leaving it at the
// default QUERY opcode (0). This is the direct regression for the bug where a
// built update decoded back to opcode 0 and was rejected by ParseUpdate.
func TestBuildUpdateHeaderOpcode(t *testing.T) {
	key := zone.ZoneKey{View: zone.View("internal"), Name: mustName(t, "example.com.")}
	ops := []zone.UpdateOp{
		{Kind: zone.OpAdd, Name: mustName(t, "host1.example.com."), Type: zone.TypeA, TTL: 300, RDATA: zone.A{IP: [4]byte{10, 0, 0, 1}}},
	}
	meta := UpdateMeta{View: "internal", OpID: "op-1", ExpectedRevision: 7, BaseActiveSerial: 20240101}

	const id uint16 = 0x1234
	msg := BuildUpdate(id, key, ops, meta)

	// Header-level checks: transaction ID preserved, opcode is UPDATE (not
	// QUERY), QR bit clear (an UPDATE is a request), and section counts match.
	h, _, err := DecodeHeader(msg, 0)
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if h.ID != id {
		t.Errorf("header ID = %#x, want %#x", h.ID, id)
	}
	if h.Opcode() != OpUpdate {
		t.Errorf("header Opcode = %d, want %d (OpUpdate)", h.Opcode(), OpUpdate)
	}
	if h.Opcode() == OpQuery {
		t.Errorf("header Opcode is QUERY (0); built UPDATE must not decode as a plain query")
	}
	if h.QR() {
		t.Errorf("header QR set; built UPDATE should be a request (QR=0)")
	}
	if h.QDCount != 1 {
		t.Errorf("QDCount = %d, want 1 (single zone section)", h.QDCount)
	}
	if h.NSCount != uint16(len(ops)) {
		t.Errorf("NSCount = %d, want %d (update section)", h.NSCount, len(ops))
	}
	if h.ARCount != 1 {
		t.Errorf("ARCount = %d, want 1 (OPT with update metadata)", h.ARCount)
	}
}

// TestBuildUpdateRoundTrip exercises the full construct -> decode -> parse
// pipeline, asserting that the zone key, every update operation kind and the
// EDNS metadata survive the wire round-trip. This is the end-to-end regression
// that fails (ParseUpdate returns "not an UPDATE opcode") when BuildUpdate
// omits the opcode.
func TestBuildUpdateRoundTrip(t *testing.T) {
	zoneName := mustName(t, "example.com.")
	key := zone.ZoneKey{View: zone.View("internal"), Name: zoneName}

	addName := mustName(t, "host1.example.com.")
	delExactName := mustName(t, "host2.example.com.")
	delName := mustName(t, "retired.example.com.")

	ops := []zone.UpdateOp{
		{Kind: zone.OpAdd, Name: addName, Type: zone.TypeA, TTL: 300, RDATA: zone.A{IP: [4]byte{10, 0, 0, 1}}},
		{Kind: zone.OpDeleteExact, Name: delExactName, Type: zone.TypeA, RDATA: zone.A{IP: [4]byte{10, 0, 0, 2}}},
		{Kind: zone.OpDeleteName, Name: delName},
	}
	meta := UpdateMeta{
		View:             "internal",
		OpID:             "op-abc-123",
		ExpectedRevision: 42,
		BaseActiveSerial: 20240101,
	}

	const id uint16 = 0xABCD
	msg := BuildUpdate(id, key, ops, meta)

	m, err := DecodeMessage(msg)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if m.Header.Opcode() != OpUpdate {
		t.Fatalf("decoded opcode = %d, want %d (OpUpdate)", m.Header.Opcode(), OpUpdate)
	}
	if m.Header.ID != id {
		t.Errorf("decoded ID = %#x, want %#x", m.Header.ID, id)
	}

	parsedKey, parsedOps, parsedMeta, err := ParseUpdate(m)
	if err != nil {
		t.Fatalf("ParseUpdate: %v", err)
	}

	if parsedKey.View != key.View || parsedKey.Name != key.Name {
		t.Errorf("parsed zone key = %s, want %s", parsedKey, key)
	}

	if len(parsedOps) != len(ops) {
		t.Fatalf("parsed %d ops, want %d", len(parsedOps), len(ops))
	}

	// Op 0: addition of an A record.
	if parsedOps[0].Kind != zone.OpAdd {
		t.Errorf("op[0] kind = %d, want OpAdd", parsedOps[0].Kind)
	}
	if parsedOps[0].Name != addName {
		t.Errorf("op[0] name = %s, want %s", parsedOps[0].Name, addName)
	}
	if parsedOps[0].Type != zone.TypeA {
		t.Errorf("op[0] type = %s, want A", parsedOps[0].Type)
	}
	if parsedOps[0].TTL != 300 {
		t.Errorf("op[0] ttl = %d, want 300", parsedOps[0].TTL)
	}
	a, ok := parsedOps[0].RDATA.(zone.A)
	if !ok {
		t.Fatalf("op[0] rdata type = %T, want zone.A", parsedOps[0].RDATA)
	}
	if a.IP != ([4]byte{10, 0, 0, 1}) {
		t.Errorf("op[0] rdata IP = %v, want 10.0.0.1", a.IP)
	}

	// Op 1: exact delete of an A record.
	if parsedOps[1].Kind != zone.OpDeleteExact {
		t.Errorf("op[1] kind = %d, want OpDeleteExact", parsedOps[1].Kind)
	}
	if parsedOps[1].Name != delExactName {
		t.Errorf("op[1] name = %s, want %s", parsedOps[1].Name, delExactName)
	}
	d, ok := parsedOps[1].RDATA.(zone.A)
	if !ok {
		t.Fatalf("op[1] rdata type = %T, want zone.A", parsedOps[1].RDATA)
	}
	if d.IP != ([4]byte{10, 0, 0, 2}) {
		t.Errorf("op[1] rdata IP = %v, want 10.0.0.2", d.IP)
	}

	// Op 2: delete all RRsets at a name.
	if parsedOps[2].Kind != zone.OpDeleteName {
		t.Errorf("op[2] kind = %d, want OpDeleteName", parsedOps[2].Kind)
	}
	if parsedOps[2].Name != delName {
		t.Errorf("op[2] name = %s, want %s", parsedOps[2].Name, delName)
	}

	// EDNS update metadata must round-trip verbatim.
	if parsedMeta == nil {
		t.Fatalf("parsed update meta is nil; OPT/EDNS metadata was not preserved")
	}
	if parsedMeta.View != meta.View {
		t.Errorf("meta View = %q, want %q", parsedMeta.View, meta.View)
	}
	if parsedMeta.OpID != meta.OpID {
		t.Errorf("meta OpID = %q, want %q", parsedMeta.OpID, meta.OpID)
	}
	if parsedMeta.ExpectedRevision != meta.ExpectedRevision {
		t.Errorf("meta ExpectedRevision = %d, want %d", parsedMeta.ExpectedRevision, meta.ExpectedRevision)
	}
	if parsedMeta.BaseActiveSerial != meta.BaseActiveSerial {
		t.Errorf("meta BaseActiveSerial = %d, want %d", parsedMeta.BaseActiveSerial, meta.BaseActiveSerial)
	}
}

// TestBuildUpdateEmptyOpsStillUpdate verifies that an UPDATE with no update
// operations still carries the UPDATE opcode and a parseable zone section, so
// empty-update probes are not misclassified as queries.
func TestBuildUpdateEmptyOpsStillUpdate(t *testing.T) {
	key := zone.ZoneKey{View: zone.View("external"), Name: mustName(t, "zone.example.")}
	msg := BuildUpdate(0xBEEF, key, nil, UpdateMeta{View: "external", OpID: "x"})

	m, err := DecodeMessage(msg)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if m.Header.Opcode() != OpUpdate {
		t.Fatalf("opcode = %d, want OpUpdate", m.Header.Opcode())
	}
	if m.Header.ID != 0xBEEF {
		t.Errorf("ID = %#x, want 0xBEEF", m.Header.ID)
	}
	if _, _, _, err := ParseUpdate(m); err != nil {
		t.Fatalf("ParseUpdate on empty update: %v", err)
	}
}
