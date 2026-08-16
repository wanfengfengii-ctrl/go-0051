package zone

import (
	"fmt"
)

// UpdateOpKind selects the semantics of an UpdateOp.
type UpdateOpKind int

const (
	// OpAdd adds a record (deduplicating exact matches).
	OpAdd UpdateOpKind = iota
	// OpDeleteExact removes the record matching name+type+rdata exactly.
	OpDeleteExact
	// OpDeleteName removes every record set at a name.
	OpDeleteName
)

// UpdateOp is a single dynamic-update primitive applied to a draft snapshot.
type UpdateOp struct {
	Kind  UpdateOpKind
	Name  Name
	Type  Type
	TTL   uint32
	RDATA RDATA // used by OpAdd and OpDeleteExact
}

// UpdateOpFromRecord builds an OpAdd from a Record.
func UpdateOpFromRecord(r Record) UpdateOp {
	return UpdateOp{Kind: OpAdd, Name: r.Name, Type: r.Type, TTL: r.TTL, RDATA: r.RDATA}
}

// Apply mutates the draft snapshot in place with the given operations, then
// validates the result. If validation fails the snapshot is left partially
// modified and the caller must discard it (drafts are not installed on error).
// The boolean reports whether any operation changed the snapshot content.
func (s *Snapshot) Apply(ops []UpdateOp) (bool, error) {
	changed := false
	for i, op := range ops {
		switch op.Kind {
		case OpAdd:
			if op.RDATA == nil {
				return changed, fmt.Errorf("zone: add op %d has no rdata", i)
			}
			if op.Type != op.RDATA.Type() {
				return changed, fmt.Errorf("zone: add op %d type %s does not match rdata", i, op.Type)
			}
			before := 0
			if rs := s.records[RRKey{op.Name, op.Type}]; rs != nil {
				before = len(rs.RDATA)
			}
			s.addRecord(op.Name, op.Type, op.TTL, op.RDATA)
			if len(s.records[RRKey{op.Name, op.Type}].RDATA) != before {
				changed = true
			}
		case OpDeleteExact:
			if op.RDATA == nil {
				return changed, fmt.Errorf("zone: delete-exact op %d has no rdata", i)
			}
			if s.deleteExact(op.Name, op.Type, op.RDATA) {
				changed = true
			}
		case OpDeleteName:
			if s.deleteName(op.Name) > 0 {
				changed = true
			}
		default:
			return changed, fmt.Errorf("zone: unknown update op kind %d", op.Kind)
		}
	}
	if err := s.Validate(); err != nil {
		return changed, err
	}
	return changed, nil
}

// SetSOASerial replaces the serial embedded in the apex SOA record. It is used
// by the coordinator when committing a draft to stamp the freshly allocated,
// strictly-increasing SOA serial onto the candidate.
func (s *Snapshot) SetSOASerial(serial uint32) error {
	key := RRKey{s.Zone.Name, TypeSOA}
	rs, ok := s.records[key]
	if !ok || len(rs.RDATA) == 0 {
		return fmt.Errorf("zone: cannot set SOA serial on zone %s without a SOA", s.Zone)
	}
	soa, ok := rs.RDATA[0].(SOA)
	if !ok {
		return fmt.Errorf("zone: apex SOA has wrong rdata type")
	}
	soa.Serial = serial
	rs.RDATA[0] = soa
	return nil
}
