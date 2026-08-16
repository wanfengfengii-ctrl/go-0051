package zone

import (
	"encoding/binary"
	"fmt"
)

// RDATA is the typed payload of a resource record. Concrete implementations
// live in this package so that the domain model can validate structural
// invariants (CNAME targets, SOA serials, required records) without depending
// on the binary codec.
type RDATA interface {
	// Type returns the RR TYPE this payload belongs to.
	Type() Type
	// Equal reports whether two payloads of the same type are identical.
	Equal(RDATA) bool
	// Canonical returns the canonical wire-form RDATA (uncompressed names)
	// used for deterministic sorting and content digests (RFC 4034 §6.2).
	Canonical() []byte
}

// SOA marks the start of a zone authority.
type SOA struct {
	MName   Name // primary master
	RName   Name // responsible-person mailbox (encoded as a name)
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

func (SOA) Type() Type   { return TypeSOA }
func (s SOA) Equal(o RDATA) bool {
	v, ok := o.(SOA)
	return ok && s == v
}
func (s SOA) Canonical() []byte {
	b := canonicalWireName(s.MName)
	b = append(b, canonicalWireName(s.RName)...)
	b = binary.BigEndian.AppendUint32(b, s.Serial)
	b = binary.BigEndian.AppendUint32(b, s.Refresh)
	b = binary.BigEndian.AppendUint32(b, s.Retry)
	b = binary.BigEndian.AppendUint32(b, s.Expire)
	b = binary.BigEndian.AppendUint32(b, s.Minimum)
	return b
}

// NS delegates a subzone to a nameserver.
type NS struct {
	NSDName Name
}

func (NS) Type() Type { return TypeNS }
func (n NS) Equal(o RDATA) bool {
	v, ok := o.(NS)
	return ok && n == v
}
func (n NS) Canonical() []byte {
	return canonicalWireName(n.NSDName)
}

// A is an IPv4 address record.
type A struct {
	IP [4]byte
}

func (A) Type() Type { return TypeA }
func (a A) Equal(o RDATA) bool {
	v, ok := o.(A)
	return ok && a == v
}
func (a A) Canonical() []byte {
	return append([]byte(nil), a.IP[:]...)
}

// AAAA is an IPv6 address record.
type AAAA struct {
	IP [16]byte
}

func (AAAA) Type() Type { return TypeAAAA }
func (a AAAA) Equal(o RDATA) bool {
	v, ok := o.(AAAA)
	return ok && a == v
}
func (a AAAA) Canonical() []byte {
	return append([]byte(nil), a.IP[:]...)
}

// CNAME aliases a name to another.
type CNAME struct {
	Target Name
}

func (CNAME) Type() Type { return TypeCNAME }
func (c CNAME) Equal(o RDATA) bool {
	v, ok := o.(CNAME)
	return ok && c == v
}
func (c CNAME) Canonical() []byte {
	return canonicalWireName(c.Target)
}

// TXT holds free-form text strings.
type TXT struct {
	Texts []string
}

func (TXT) Type() Type { return TypeTXT }
func (t TXT) Equal(o RDATA) bool {
	v, ok := o.(TXT)
	if !ok || len(t.Texts) != len(v.Texts) {
		return false
	}
	for i := range t.Texts {
		if t.Texts[i] != v.Texts[i] {
			return false
		}
	}
	return true
}
func (t TXT) Canonical() []byte {
	var buf []byte
	for _, s := range t.Texts {
		if len(s) > 255 {
			// Character-strings cannot exceed 255 octets; clamp defensively.
			s = s[:255]
		}
		buf = append(buf, byte(len(s)))
		buf = append(buf, s...)
	}
	return buf
}

// rdataFromType returns a zero-valued RDATA for the given type or nil if the
// type is unsupported by the domain model.
func rdataFromType(t Type) RDATA {
	switch t {
	case TypeSOA:
		return SOA{}
	case TypeNS:
		return NS{}
	case TypeA:
		return A{}
	case TypeAAAA:
		return AAAA{}
	case TypeCNAME:
		return CNAME{}
	case TypeTXT:
		return TXT{}
	default:
		return nil
	}
}

// SupportedType reports whether the type is one the model can validate.
func SupportedType(t Type) bool { return rdataFromType(t) != nil }

// describeRDATA returns a short human-readable summary for diagnostics.
func describeRDATA(r RDATA) string {
	switch v := r.(type) {
	case SOA:
		return fmt.Sprintf("SOA %s %s serial=%d", v.MName, v.RName, v.Serial)
	case NS:
		return fmt.Sprintf("NS %s", v.NSDName)
	case A:
		return fmt.Sprintf("A %d.%d.%d.%d", v.IP[0], v.IP[1], v.IP[2], v.IP[3])
	case AAAA:
		return fmt.Sprintf("AAAA %x", v.IP[:])
	case CNAME:
		return fmt.Sprintf("CNAME %s", v.Target)
	case TXT:
		return fmt.Sprintf("TXT %v", v.Texts)
	default:
		return "RDATA?"
	}
}
