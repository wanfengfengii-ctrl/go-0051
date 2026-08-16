package zone

import (
	"bytes"
	"errors"
	"testing"
)

func mustName(t *testing.T, s string) Name {
	t.Helper()
	n, err := NormalizeName(s)
	if err != nil {
		t.Fatalf("NormalizeName(%q): %v", s, err)
	}
	return n
}

func apexSOA(serial uint32) SOA {
	return SOA{
		MName:   MustNormalizeName("ns1.example.com."),
		RName:   MustNormalizeName("hostmaster.example.com."),
		Serial:  serial,
		Refresh: 3600,
		Retry:   900,
		Expire:  1209600,
		Minimum: 300,
	}
}

func baseSnapshot(t *testing.T, serial uint32, state State) *Snapshot {
	t.Helper()
	key := ZoneKey{View: "internal", Name: MustNormalizeName("example.com.")}
	s := NewSnapshot(key, serial, uint64(serial), state)
	s.addRecord(key.Name, TypeSOA, 300, apexSOA(serial))
	s.addRecord(key.Name, TypeNS, 300, NS{MustNormalizeName("ns1.example.com.")})
	return s
}

func TestNormalizeName(t *testing.T) {
	cases := []struct {
		in   string
		want Name
	}{
		{"example.com", "example.com."},
		{"EXAMPLE.COM", "example.com."},
		{"example.com.", "example.com."},
		{".", "."},
		{"", "."},
		{"a.b.c.example.com", "a.b.c.example.com."},
	}
	for _, c := range cases {
		got, err := NormalizeName(c.in)
		if err != nil {
			t.Fatalf("NormalizeName(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("NormalizeName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeNameErrors(t *testing.T) {
	bad := []string{"-bad.example.com", "a..b.example.com", "excessive" + repeat("x", 64) + ".example.com", "under_score.example.com"}
	for _, in := range bad {
		if _, err := NormalizeName(in); err == nil {
			t.Errorf("NormalizeName(%q) expected error", in)
		}
	}
}

func TestNormalizeNameWireLengthBoundary(t *testing.T) {
	label63 := repeat("a", 63)
	cases := []struct {
		name    string
		in      string
		want    Name
		wantErr bool
	}{
		{name: "root", in: ".", want: "."},
		{name: "ordinary", in: "WWW.Example.COM", want: "www.example.com."},
		{name: "maximum wire length", in: label63 + "." + label63 + "." + label63 + "." + repeat("b", 61), want: Name(label63 + "." + label63 + "." + label63 + "." + repeat("b", 61) + ".")},
		{name: "overlong by one octet", in: label63 + "." + label63 + "." + label63 + "." + repeat("b", 62), wantErr: true},
		{name: "overlong by two octets", in: label63 + "." + label63 + "." + label63 + "." + label63, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeName(tc.in)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidName) {
					t.Fatalf("NormalizeName() error = %v, want ErrInvalidName", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeName() unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("NormalizeName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func TestCompareName(t *testing.T) {
	// RFC 4034 §6.1 example fragments.
	names := []Name{
		MustNormalizeName("example."),
		MustNormalizeName("a.example."),
		MustNormalizeName("yljkjljk.a.example."),
		MustNormalizeName("z.example."),
	}
	for i := 0; i < len(names)-1; i++ {
		if c := CompareName(names[i], names[i+1]); c >= 0 {
			t.Errorf("CompareName(%s,%s) = %d, want <0", names[i], names[i+1], c)
		}
	}
	if c := CompareName(mustName(t, "example.com."), mustName(t, "example.com.")); c != 0 {
		t.Errorf("equal names compare = %d, want 0", c)
	}
	if c := CompareName(mustName(t, "host.example.com."), mustName(t, "www.example.com.")); c >= 0 {
		t.Errorf("host vs www = %d, want <0 (h<w)", c)
	}
}

func TestSnapshotCloneIndependent(t *testing.T) {
	a := baseSnapshot(t, 1, StateActive)
	b := a.Clone()
	b.deleteName(b.Zone.Name)
	if len(a.records) == 0 {
		t.Fatal("clone mutated original")
	}
}

func TestSnapshotSortedRecords(t *testing.T) {
	s := baseSnapshot(t, 1, StateActive)
	s.addRecord(mustName(t, "www.example.com."), TypeA, 300, A{IP: [4]byte{10, 0, 0, 2}})
	s.addRecord(mustName(t, "www.example.com."), TypeA, 300, A{IP: [4]byte{10, 0, 0, 1}})
	s.addRecord(mustName(t, "api.example.com."), TypeA, 300, A{IP: [4]byte{10, 0, 0, 3}})
	s.addRecord(mustName(t, "api.example.com."), TypeAAAA, 300, AAAA{})

	recs := s.SortedRecords()
	if len(recs) != 6 {
		t.Fatalf("got %d records, want 6", len(recs))
	}
	// Apex first (canonical: apex is shortest suffix). At the apex, type order
	// is NS (2) then SOA (6); then api (A, AAAA); then www (A, A).
	if recs[0].Name != s.Zone.Name || recs[0].Type != TypeNS {
		t.Errorf("first record = %s %s, want apex NS", recs[0].Name, recs[0].Type)
	}
	if recs[1].Type != TypeSOA {
		t.Errorf("second record type = %s, want SOA", recs[1].Type)
	}
	if recs[2].Name != mustName(t, "api.example.com.") || recs[2].Type != TypeA {
		t.Errorf("third = %s %s, want api A", recs[2].Name, recs[2].Type)
	}
	if recs[3].Type != TypeAAAA {
		t.Errorf("fourth type = %s, want AAAA", recs[3].Type)
	}
	if recs[4].Name != mustName(t, "www.example.com.") {
		t.Errorf("fifth name = %s, want www", recs[4].Name)
	}
	// www A records ordered by canonical RDATA (10.0.0.1 before 10.0.0.2).
	w0 := recs[4].RDATA.(A)
	if w0.IP != [4]byte{10, 0, 0, 1} {
		t.Errorf("www A not canonical-sorted: got %v", w0.IP)
	}
}

func TestApplyAddDelete(t *testing.T) {
	s := baseSnapshot(t, 1, StateDraft)
	ops := []UpdateOp{
		UpdateOpFromRecord(Record{Name: mustName(t, "www.example.com."), Type: TypeA, TTL: 300, RDATA: A{IP: [4]byte{10, 0, 0, 1}}}),
		UpdateOpFromRecord(Record{Name: mustName(t, "www.example.com."), Type: TypeA, TTL: 300, RDATA: A{IP: [4]byte{10, 0, 0, 2}}}),
	}
	if changed, err := s.Apply(ops); err != nil || !changed {
		t.Fatalf("apply add: changed=%v err=%v", changed, err)
	}
	if rs := s.Get(RRKey{mustName(t, "www.example.com."), TypeA}); rs == nil || len(rs.RDATA) != 2 {
		t.Fatalf("expected 2 A records, got %v", rs)
	}
	// Delete exact one.
	if changed, err := s.Apply([]UpdateOp{{Kind: OpDeleteExact, Name: mustName(t, "www.example.com."), Type: TypeA, RDATA: A{IP: [4]byte{10, 0, 0, 1}}}}); err != nil || !changed {
		t.Fatalf("delete exact: changed=%v err=%v", changed, err)
	}
	if rs := s.Get(RRKey{mustName(t, "www.example.com."), TypeA}); rs == nil || len(rs.RDATA) != 1 {
		t.Fatalf("expected 1 A record after delete, got %v", rs)
	}
	// Delete name group.
	if changed, err := s.Apply([]UpdateOp{{Kind: OpDeleteName, Name: mustName(t, "www.example.com.")}}); err != nil || !changed {
		t.Fatalf("delete name: changed=%v err=%v", changed, err)
	}
	if rs := s.Get(RRKey{mustName(t, "www.example.com."), TypeA}); rs != nil {
		t.Fatalf("expected no A record after delete-name, got %v", rs)
	}
}

func TestValidateRejectsMissingSOA(t *testing.T) {
	s := baseSnapshot(t, 1, StateDraft)
	s.deleteName(s.Zone.Name)
	if err := s.Validate(); err == nil {
		t.Fatal("expected validation error for missing SOA/NS")
	}
}

func TestValidateRejectsCNAMECoexistence(t *testing.T) {
	s := baseSnapshot(t, 1, StateDraft)
	s.addRecord(mustName(t, "alias.example.com."), TypeCNAME, 300, CNAME{Target: mustName(t, "www.example.com.")})
	s.addRecord(mustName(t, "alias.example.com."), TypeA, 300, A{IP: [4]byte{1, 2, 3, 4}})
	if err := s.Validate(); err == nil {
		t.Fatal("expected CNAME/A coexistence rejection")
	}
}

func TestValidateRejectsOutsideZone(t *testing.T) {
	s := baseSnapshot(t, 1, StateDraft)
	s.addRecord(mustName(t, "host.other.com."), TypeA, 300, A{IP: [4]byte{1, 2, 3, 4}})
	if err := s.Validate(); err == nil {
		t.Fatal("expected out-of-zone rejection")
	}
}

func TestSetSOASerial(t *testing.T) {
	s := baseSnapshot(t, 1, StateDraft)
	if err := s.SetSOASerial(42); err != nil {
		t.Fatal(err)
	}
	if s.SOA().(SOA).Serial != 42 {
		t.Errorf("SOA serial = %d, want 42", s.SOA().(SOA).Serial)
	}
}

func TestRDATAEqualAndCanonical(t *testing.T) {
	a := A{IP: [4]byte{1, 2, 3, 4}}
	if !a.Equal(A{IP: [4]byte{1, 2, 3, 4}}) {
		t.Error("A.Equal identical failed")
	}
	if a.Equal(A{IP: [4]byte{1, 2, 3, 5}}) {
		t.Error("A.Equal different succeeded")
	}
	if !bytes.Equal(a.Canonical(), []byte{1, 2, 3, 4}) {
		t.Errorf("A.Canonical = %v", a.Canonical())
	}
	soa := apexSOA(7)
	if soa.Equal(apexSOA(8)) {
		t.Error("SOA equal with different serial succeeded")
	}
}
