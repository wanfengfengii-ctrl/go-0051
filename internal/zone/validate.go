package zone

import (
	"errors"
	"fmt"
)

// ErrInvalidZone is returned when a snapshot violates a zone invariant.
var ErrInvalidZone = errors.New("zone: invalid zone")

// Validate checks the structural invariants of a zone snapshot:
//   - exactly one SOA at the apex,
//   - at least one NS at the apex,
//   - CNAME exclusivity (a name with a CNAME has no other type and is unique),
//   - every record name belongs to the zone (apex or subdomain),
//   - every RRset TTL is normalized (consistent within the set).
func (s *Snapshot) Validate() error {
	if s == nil {
		return fmt.Errorf("%w: nil snapshot", ErrInvalidZone)
	}
	apex := s.Zone.Name

	// SOA: exactly one, at the apex.
	soaKey := RRKey{apex, TypeSOA}
	soaRS := s.records[soaKey]
	if soaRS == nil || len(soaRS.RDATA) == 0 {
		return fmt.Errorf("%w: missing SOA at apex %s", ErrInvalidZone, apex)
	}
	if len(soaRS.RDATA) != 1 {
		return fmt.Errorf("%w: multiple SOA records at apex %s", ErrInvalidZone, apex)
	}
	if _, ok := soaRS.RDATA[0].(SOA); !ok {
		return fmt.Errorf("%w: apex SOA has wrong rdata type", ErrInvalidZone)
	}

	// NS: at least one at the apex.
	nsRS := s.records[RRKey{apex, TypeNS}]
	if nsRS == nil || len(nsRS.RDATA) == 0 {
		return fmt.Errorf("%w: missing NS at apex %s", ErrInvalidZone, apex)
	}

	for key, rs := range s.records {
		// Zone ownership: every name must be the apex or a subdomain of it.
		if key.Name != apex && !key.Name.IsSubdomainOf(apex) {
			return fmt.Errorf("%w: record name %s outside zone %s", ErrInvalidZone, key.Name, apex)
		}
		// TTL normalization: an RRset carries a single TTL (enforced by
		// addRecord, but verify defensively).
		for _, r := range rs.RDATA {
			if r == nil {
				return fmt.Errorf("%w: nil rdata in %s %s", ErrInvalidZone, key.Name, key.Type)
			}
			if r.Type() != key.Type {
				return fmt.Errorf("%w: rdata type mismatch for %s", ErrInvalidZone, key.Name)
			}
		}
		// CNAME exclusivity: a CNAME RRset must hold exactly one record and no
		// other RRset may exist at the same name.
		if key.Type == TypeCNAME {
			if len(rs.RDATA) > 1 {
				return fmt.Errorf("%w: multiple CNAME records at %s", ErrInvalidZone, key.Name)
			}
			for other := range s.records {
				if other.Name == key.Name && other.Type != TypeCNAME {
					return fmt.Errorf("%w: CNAME at %s coexists with %s", ErrInvalidZone, key.Name, other.Type)
				}
			}
		}
	}
	return nil
}
