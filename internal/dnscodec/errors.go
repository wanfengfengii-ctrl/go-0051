// Package dnscodec implements the DNS binary wire format (RFC 1035) used by the
// coordinator's data plane, plus the restricted RFC 2136 UPDATE semantics and
// the private EDNS options that carry management metadata.
//
// The decoder is written defensively: it never reads past the supplied packet
// boundary, tracks compression-pointer jumps to bound depth and reject cycles,
// and returns stable, classifiable sentinel errors rather than ad-hoc strings.
// Callers can distinguish "the message was truncated" (ErrTruncated) from "a
// name was malformed or a compression pointer was illegal" (ErrCompressionPointer)
// using errors.Is.
package dnscodec

import "errors"

// Stable error categories. Wrapping sub-errors with these sentinels keeps the
// classification stable across the system: truncation, compression-pointer
// faults and generic invalid-message conditions are mutually distinct.
var (
	// ErrTruncated means a required field, RDLENGTH extent or TCP frame was not
	// fully present within the packet boundary. Truncation is recoverable in the
	// sense that a longer frame might have made the message valid.
	ErrTruncated = errors.New("dnscodec: message truncated")
	// ErrCompressionPointer means a name was illegal or a compression pointer
	// was out of bounds, cyclic, too deep, or used a reserved label type. These
	// are treated as malformed-name faults, distinct from truncation.
	ErrCompressionPointer = errors.New("dnscodec: compression pointer error")
	// ErrInvalidMessage means the message was structurally parsable but
	// semantically invalid (bad counts, unsupported class, bad opcode, etc.).
	ErrInvalidMessage = errors.New("dnscodec: invalid message")
)

const (
	// maxPointerJumps bounds the number of compression-pointer dereferences
	// allowed while decoding a single name. 127 is far above any legal use and
	// makes cycle detection with a visited set redundant in practice, but both
	// guards are applied.
	maxPointerJumps = 127
	// maxLabelLength is the maximum legal label length in octets.
	maxLabelLength = 63
)

// DNS class values used by the coordinator.
const (
	ClassIN uint16 = 1
	// ClassNONE and ClassANY are used in RFC 2136 UPDATE prerequisites/updates.
	ClassNONE uint16 = 254
	ClassANY  uint16 = 255
)

// Opcode values.
const (
	OpQuery  uint16 = 0
	OpUpdate uint16 = 5
)

// RCODE values.
const (
	RcodeNoError  uint16 = 0
	RcodeFormErr  uint16 = 1
	RcodeNotImpl  uint16 = 4
	RcodeRefused  uint16 = 5
	RcodeNXDomain uint16 = 3
	RcodeYXDomain uint16 = 6
	RcodeYXRRSet  uint16 = 7
	RcodeNXRRSet  uint16 = 8
)
