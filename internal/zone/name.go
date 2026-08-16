// Package zone defines the authoritative DNS zone domain model.
//
// The consistency boundary in this system is the (View, ZoneName) pair: every
// mutation, snapshot and transfer is scoped to exactly one zone under one view.
// Snapshots are immutable once created; draft state lives in the coordinator
// which produces new snapshots rather than mutating existing ones.
package zone

import (
	"errors"
	"fmt"
	"strings"
)

// Name is a canonical, fully-qualified domain name. Names are lowercased and
// always carry a trailing dot (the root label "" is represented as ".").
type Name string

// View is a DNS view identifier (e.g. "internal", "external").
type View string

// Type is a DNS RR TYPE.
type Type uint16

// RR types understood by the coordinator. The set is intentionally limited to
// the types the domain model can validate: SOA, NS, A, AAAA, CNAME and TXT.
const (
	TypeA     Type = 1
	TypeNS    Type = 2
	TypeCNAME Type = 5
	TypeSOA   Type = 6
	TypeTXT   Type = 16
	TypeAAAA  Type = 28
	TypeOPT   Type = 41
	TypeAXFR  Type = 252
	TypeANY   Type = 255
)

// String returns the standard mnemonic for a type.
func (t Type) String() string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeOPT:
		return "OPT"
	case TypeAXFR:
		return "AXFR"
	case TypeANY:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", uint16(t))
	}
}

// ZoneKey identifies a single consistency boundary: one zone under one view.
type ZoneKey struct {
	View View
	Name Name
}

// String renders a zone key as "view/name".
func (k ZoneKey) String() string {
	return fmt.Sprintf("%s/%s", k.View, k.Name)
}

// ErrInvalidName is returned when a name cannot be normalized.
var ErrInvalidName = errors.New("zone: invalid name")

// NormalizeName parses a textual domain name and returns its canonical form.
// The input may omit the trailing dot and may use any case; the result is
// lowercased and ends with a single dot. The root zone is ".".
func NormalizeName(s string) (Name, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return Name("."), nil
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if err := validateLabel(l); err != nil {
			return "", err
		}
	}
	return Name(strings.ToLower(s) + "."), nil
}

// MustNormalizeName panics on invalid input; for use in tests and constants.
func MustNormalizeName(s string) Name {
	n, err := NormalizeName(s)
	if err != nil {
		panic(err)
	}
	return n
}

func validateLabel(l string) error {
	if len(l) == 0 {
		return fmt.Errorf("%w: empty label", ErrInvalidName)
	}
	if len(l) > 63 {
		return fmt.Errorf("%w: label %q exceeds 63 octets", ErrInvalidName, l)
	}
	for _, c := range l {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			return fmt.Errorf("%w: illegal octet %q in label %q", ErrInvalidName, c, l)
		}
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return fmt.Errorf("%w: label %q must not start or end with a hyphen", ErrInvalidName, l)
	}
	return nil
}

// String returns the textual form of the name.
func (n Name) String() string { return string(n) }

// IsRoot reports whether the name is the DNS root.
func (n Name) IsRoot() bool { return n == "." || n == "" }

// Labels returns the labels of the name ordered from the apex-most label to
// the TLD (left to right as written). The root has no labels.
func (n Name) Labels() []string {
	if n.IsRoot() {
		return nil
	}
	s := strings.TrimSuffix(string(n), ".")
	return strings.Split(s, ".")
}

// Parent returns the parent name of n, or the root if n is already the root or
// a single label. The parent of "a.b.example." is "b.example.".
func (n Name) Parent() Name {
	labels := n.Labels()
	if len(labels) <= 1 {
		return Name(".")
	}
	return Name(strings.Join(labels[1:], ".") + ".")
}

// IsSubdomainOf reports whether n is equal to or a subdomain of parent.
func (n Name) IsSubdomainOf(parent Name) bool {
	if parent.IsRoot() {
		return true
	}
	if n == parent {
		return true
	}
	return strings.HasSuffix(string(n), "."+string(parent))
}

// CompareName implements the canonical DNS name ordering (RFC 4034 §6.1):
// labels are compared right to left as byte strings; if one name is a proper
// suffix of the other the shorter name sorts first.
func CompareName(a, b Name) int {
	la, lb := a.Labels(), b.Labels()
	for i := 0; i < len(la) && i < len(lb); i++ {
		ai := len(la) - 1 - i
		bi := len(lb) - 1 - i
		if c := strings.Compare(la[ai], lb[bi]); c != 0 {
			return c
		}
	}
	return len(la) - len(lb)
}

// canonicalWireName returns the uncompressed wire encoding of a name: a
// sequence of length-prefixed labels terminated by a zero-length label. Names
// are stored lowercased so this is already in canonical form (RFC 4034 §6.2).
func canonicalWireName(n Name) []byte {
	if n.IsRoot() {
		return []byte{0}
	}
	var buf []byte
	for _, l := range n.Labels() {
		buf = append(buf, byte(len(l)))
		buf = append(buf, l...)
	}
	buf = append(buf, 0)
	return buf
}
