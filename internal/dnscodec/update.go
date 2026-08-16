package dnscodec

import (
	"fmt"

	"intranet-dns-zone-release-coordinator/internal/zone"
)

// UpdateOperation is a decoded RFC 2136 UPDATE operation drawn from the UPDATE
// section of a message. The coordinator supports a restricted subset:
//   - Add: insert a record (TTL and RDATA meaningful).
//   - DeleteExact: delete the record matching name+type+rdata (TTL ignored).
//   - DeleteName: delete every RRset at name (type=ANY, rdlength=0).
//
// RFC 2136 prerequisites are not used: the coordinator performs optimistic
// concurrency via expected revision/serial instead.
type UpdateOperation struct {
	Kind  zone.UpdateOpKind
	Name  zone.Name
	Type  zone.Type
	TTL   uint32
	RDATA zone.RDATA
}

// ParseUpdate converts an RFC 2136 UPDATE message into the target zone and a
// list of update operations. The UPDATE zone is carried as the single "zone"
// RR in the message's Zone section (encoded in the question section per RFC
// 2136 §3.2.1, where ZTYPE=SOA, ZCLASS=IN).
func ParseUpdate(m Message) (zone.ZoneKey, []UpdateOperation, *UpdateMeta, error) {
	if m.Header.Opcode() != OpUpdate {
		return zone.ZoneKey{}, nil, nil, fmt.Errorf("%w: not an UPDATE opcode", ErrInvalidMessage)
	}
	if len(m.Question) != 1 {
		return zone.ZoneKey{}, nil, nil, fmt.Errorf("%w: UPDATE needs exactly one zone section", ErrInvalidMessage)
	}
	zq := m.Question[0]
	if zq.Type != zone.TypeSOA {
		return zone.ZoneKey{}, nil, nil, fmt.Errorf("%w: UPDATE zone type must be SOA", ErrInvalidMessage)
	}
	if zq.Class != ClassIN {
		return zone.ZoneKey{}, nil, nil, fmt.Errorf("%w: UPDATE zone class must be IN", ErrInvalidMessage)
	}

	opt := FindOPT(m)
	var meta *UpdateMeta
	if opt != nil {
		um, err := DecodeUpdateMeta(opt)
		if err != nil {
			return zone.ZoneKey{}, nil, nil, err
		}
		meta = &um
	}
	view := ""
	if meta != nil {
		view = meta.View
	}
	key := zone.ZoneKey{View: zone.View(view), Name: zq.Name}

	ops := make([]UpdateOperation, 0, len(m.Authority))
	for _, rr := range m.Authority {
		op, err := rrToUpdateOp(rr)
		if err != nil {
			return key, nil, nil, err
		}
		ops = append(ops, op)
	}
	return key, ops, meta, nil
}

func rrToUpdateOp(rr RR) (UpdateOperation, error) {
	switch {
	case rr.Class == ClassIN && rr.RDATA != nil:
		// Addition: NAME TYPE IN TTL RDATA.
		return UpdateOperation{Kind: zone.OpAdd, Name: rr.Name, Type: rr.Type, TTL: rr.TTL, RDATA: rr.RDATA}, nil
	case rr.Class == ClassNONE && rr.RDATA != nil:
		// Delete an RR: NAME TYPE NONE TTL RDATA (TTL ignored).
		if raw, ok := rr.RDATA.(RawRDATA); ok && len(raw.Bytes) == 0 {
			return UpdateOperation{}, fmt.Errorf("%w: NONE delete needs rdata", ErrInvalidMessage)
		}
		return UpdateOperation{Kind: zone.OpDeleteExact, Name: rr.Name, Type: rr.Type, RDATA: rr.RDATA}, nil
	case rr.Class == ClassANY && rr.Type == zone.TypeANY:
		// Delete all RRsets from a name.
		return UpdateOperation{Kind: zone.OpDeleteName, Name: rr.Name}, nil
	case rr.Class == ClassANY:
		// Delete an RRset (all records of name+type). Represent as a
		// delete-exact of a sentinel is not faithful; instead map to a
		// delete-name of the specific type by delegating to the snapshot,
		// which exposes DeleteRRSet. We surface it as a typed delete-name so
		// the coordinator can apply DeleteRRSet.
		return UpdateOperation{Kind: opDeleteRRSet, Name: rr.Name, Type: rr.Type}, nil
	default:
		return UpdateOperation{}, fmt.Errorf("%w: unsupported UPDATE RR class/type", ErrInvalidMessage)
	}
}

// opDeleteRRSet is an internal kind extending zone.UpdateOpKind for RRset-wide
// deletion. It is kept private to the codec layer; the coordinator translates
// it to zone snapshot operations.
const opDeleteRRSet zone.UpdateOpKind = 100

// ToZoneOps converts codec update operations to zone update operations. RRset
// deletes are converted to a delete-exact-per-existing-record by the caller
// (the coordinator resolves them against the draft).
func ToZoneOps(ops []UpdateOperation) []zone.UpdateOp {
	out := make([]zone.UpdateOp, 0, len(ops))
	for _, o := range ops {
		if o.Kind == opDeleteRRSet {
			// Represent as a name delete scoped to a type via a marker; the
			// coordinator resolves this against current records.
			out = append(out, zone.UpdateOp{Kind: opDeleteRRSet, Name: o.Name, Type: o.Type})
			continue
		}
		out = append(out, zone.UpdateOp{Kind: o.Kind, Name: o.Name, Type: o.Type, TTL: o.TTL, RDATA: o.RDATA})
	}
	return out
}

// BuildUpdate constructs a DNS UPDATE message targeting zone key with the given
// operations and optional metadata.
func BuildUpdate(id uint16, key zone.ZoneKey, ops []zone.UpdateOp, meta UpdateMeta) []byte {
	q := Question{Name: key.Name, Type: zone.TypeSOA, Class: ClassIN}
	auth := make([]RR, 0, len(ops))
	for _, op := range ops {
		switch op.Kind {
		case zone.OpAdd:
			auth = append(auth, RR{Name: op.Name, Type: op.Type, Class: ClassIN, TTL: op.TTL, RDATA: op.RDATA})
		case zone.OpDeleteExact:
			auth = append(auth, RR{Name: op.Name, Type: op.Type, Class: ClassNONE, TTL: 0, RDATA: op.RDATA})
		case zone.OpDeleteName:
			auth = append(auth, RR{Name: op.Name, Type: zone.TypeANY, Class: ClassANY, TTL: 0, RDATA: RawRDATA{TypeCode: zone.TypeANY}})
		case opDeleteRRSet:
			auth = append(auth, RR{Name: op.Name, Type: op.Type, Class: ClassANY, TTL: 0, RDATA: RawRDATA{TypeCode: op.Type}})
		}
	}
	header := Header{ID: id}
	header.SetOpcode(OpUpdate)
	m := Message{
		Header:     header,
		Question:   []Question{q},
		Authority:  auth,
		Additional: []RR{EncodeUpdateMetaOption(meta)},
	}
	return EncodeMessage(m)
}
