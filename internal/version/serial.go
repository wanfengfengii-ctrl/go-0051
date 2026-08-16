// Package version owns the SOA serial allocation rules for a zone.
//
// Every successful draft commit produces a new, strictly increasing uint32 SOA
// serial that is never reused, even across restarts. The allocator is
// persisted as part of the checkpoint so that a restarted coordinator cannot
// hand out a serial that was already observed by secondaries.
package version

import (
	"errors"
	"fmt"
)

// ErrSerialExhausted is returned when the uint32 serial space is exhausted.
// The allocator never wraps around; once the maximum value has been issued no
// further serials can be allocated for that zone.
var ErrSerialExhausted = errors.New("version: SOA serial space exhausted")

// MaxSerial is the largest serial the allocator will ever issue.
const MaxSerial uint32 = ^uint32(0)

// SerialAllocator issues strictly increasing, never-reused uint32 serials.
//
// "Last" is the most recent serial issued (or the seed value). The next call to
// Next returns Last+1 (unless Last is MaxSerial). The allocator deliberately
// does not wrap: reaching MaxSerial is a terminal, reportable condition.
type SerialAllocator struct {
	last uint32
}

// NewSerialAllocator seeds an allocator whose next issued serial will be
// last+1. A freshly created zone seeds with 0 so the first issued serial is 1.
func NewSerialAllocator(last uint32) *SerialAllocator {
	return &SerialAllocator{last: last}
}

// Last returns the most recently issued serial (or the seed if none issued).
func (a *SerialAllocator) Last() uint32 { return a.last }

// Peek returns the serial that Next would issue without advancing state. It
// returns ErrSerialExhausted if the space is exhausted.
func (a *SerialAllocator) Peek() (uint32, error) {
	if a.last == MaxSerial {
		return 0, ErrSerialExhausted
	}
	return a.last + 1, nil
}

// Next issues and returns the next serial, advancing internal state.
// It returns ErrSerialExhausted if the maximum serial has already been issued.
func (a *SerialAllocator) Next() (uint32, error) {
	if a.last == MaxSerial {
		return 0, fmt.Errorf("%w: last issued serial was %d", ErrSerialExhausted, a.last)
	}
	a.last++
	return a.last, nil
}

// Restore sets the allocator to a recovered last-issued serial. It is used by
// the recovery path after a checkpoint load. Restoring to a value less than the
// current last is rejected to preserve the never-decrease invariant.
func (a *SerialAllocator) Restore(last uint32) error {
	if last < a.last {
		return fmt.Errorf("version: restore %d would decrease below current %d", last, a.last)
	}
	a.last = last
	return nil
}

// AdvanceTo moves the allocator forward to at least serial, preserving the
// never-decrease invariant. It is used when replaying journal entries that
// recorded an issued serial, so that replayed effects do not re-issue serials.
func (a *SerialAllocator) AdvanceTo(serial uint32) error {
	if serial < a.last {
		return fmt.Errorf("version: advance to %d below current %d", serial, a.last)
	}
	a.last = serial
	return nil
}
