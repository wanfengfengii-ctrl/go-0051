package zone

import (
	"bytes"
	"sort"
)

// State is the lifecycle stage of a snapshot.
type State int

const (
	// StateDraft: a mutable working version, never observable by query or AXFR.
	StateDraft State = iota
	// StatePending: a sealed, immutable candidate awaiting publication.
	StatePending
	// StateActive: the version currently served by authoritative queries.
	StateActive
	// StateRetired: a superseded version kept only for in-flight transfers.
	StateRetired
)

// String returns the lifecycle name.
func (s State) String() string {
	switch s {
	case StateDraft:
		return "draft"
	case StatePending:
		return "pending"
	case StateActive:
		return "active"
	case StateRetired:
		return "retired"
	default:
		return "unknown"
	}
}

// RRKey identifies a resource record set within a snapshot.
type RRKey struct {
	Name Name
	Type Type
}

// RRSet is a set of records sharing name, type and TTL.
type RRSet struct {
	TTL   uint32
	RDATA []RDATA
}

// Record is a single resource record as exposed to callers.
type Record struct {
	Name  Name
	Type  Type
	TTL   uint32
	RDATA RDATA
}

// Snapshot is an immutable, validated view of a zone at a single revision.
type Snapshot struct {
	Zone     ZoneKey
	Serial   uint32 // SOA serial (strictly increasing, never reused)
	Revision uint64 // internal monotonic revision
	State    State
	records  map[RRKey]*RRSet
}

// NewSnapshot constructs an empty snapshot for a zone. The records map is
// private; callers build content with ApplyUpdate on a cloned draft.
func NewSnapshot(key ZoneKey, serial uint32, revision uint64, state State) *Snapshot {
	return &Snapshot{
		Zone:    key,
		Serial:  serial,
		Revision: revision,
		State:   state,
		records: make(map[RRKey]*RRSet),
	}
}

// Clone returns a deep copy of the snapshot suitable for mutation. The clone
// shares no map or slice with the original.
func (s *Snapshot) Clone() *Snapshot {
	if s == nil {
		return nil
	}
	c := &Snapshot{
		Zone:    s.Zone,
		Serial:  s.Serial,
		Revision: s.Revision,
		State:   s.State,
		records: make(map[RRKey]*RRSet, len(s.records)),
	}
	for k, rs := range s.records {
		nr := make([]RDATA, len(rs.RDATA))
		copy(nr, rs.RDATA)
		c.records[k] = &RRSet{TTL: rs.TTL, RDATA: nr}
	}
	return c
}

// Get returns the RRset for a key, or nil if absent.
func (s *Snapshot) Get(key RRKey) *RRSet { return s.records[key] }

// RRKeys returns the keys present in the snapshot.
func (s *Snapshot) RRKeys() []RRKey {
	keys := make([]RRKey, 0, len(s.records))
	for k := range s.records {
		keys = append(keys, k)
	}
	return keys
}

// SOA returns the zone's SOA record, or nil if none.
func (s *Snapshot) SOA() RDATA {
	if rs := s.records[RRKey{s.Zone.Name, TypeSOA}]; rs != nil && len(rs.RDATA) > 0 {
		return rs.RDATA[0]
	}
	return nil
}

// HasSOA reports whether the snapshot contains exactly one SOA at the apex.
func (s *Snapshot) HasSOA() bool { return s.SOA() != nil }

// SortedRecords returns all records in canonical order: by name (RFC 4034
// canonical ordering), then type, then canonical RDATA. The SOA is included.
func (s *Snapshot) SortedRecords() []Record {
	out := make([]Record, 0)
	for key, rs := range s.records {
		for _, r := range rs.RDATA {
			out = append(out, Record{Name: key.Name, Type: key.Type, TTL: rs.TTL, RDATA: r})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if c := CompareName(out[i].Name, out[j].Name); c != 0 {
			return c < 0
		}
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return bytes.Compare(out[i].RDATA.Canonical(), out[j].RDATA.Canonical()) < 0
	})
	return out
}

// Apex returns the apex name of the zone.
func (s *Snapshot) Apex() Name { return s.Zone.Name }

// addRecord inserts rdata into the snapshot, normalizing the RRset TTL to the
// first-seen TTL. It is only used while constructing a draft.
func (s *Snapshot) addRecord(name Name, t Type, ttl uint32, r RDATA) {
	key := RRKey{name, t}
	rs, ok := s.records[key]
	if !ok {
		s.records[key] = &RRSet{TTL: ttl, RDATA: []RDATA{r}}
		return
	}
	for _, existing := range rs.RDATA {
		if existing.Equal(r) {
			return // deduplicate exact records
		}
	}
	rs.RDATA = append(rs.RDATA, r)
	sortRDATA(rs.RDATA)
}

// deleteExact removes a record matching r exactly. It returns whether anything
// was removed.
func (s *Snapshot) deleteExact(name Name, t Type, r RDATA) bool {
	key := RRKey{name, t}
	rs, ok := s.records[key]
	if !ok {
		return false
	}
	for i, existing := range rs.RDATA {
		if existing.Equal(r) {
			rs.RDATA = append(rs.RDATA[:i], rs.RDATA[i+1:]...)
			if len(rs.RDATA) == 0 {
				delete(s.records, key)
			}
			return true
		}
	}
	return false
}

// deleteName removes every record at a given name.
func (s *Snapshot) deleteName(name Name) int {
	removed := 0
	for key := range s.records {
		if key.Name == name {
			removed += len(s.records[key].RDATA)
			delete(s.records, key)
		}
	}
	return removed
}

func sortRDATA(rs []RDATA) {
	sort.Slice(rs, func(i, j int) bool {
		return bytes.Compare(rs[i].Canonical(), rs[j].Canonical()) < 0
	})
}
