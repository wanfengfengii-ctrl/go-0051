package dnscodec

import (
	"encoding/binary"
	"fmt"

	"intranet-dns-zone-release-coordinator/internal/zone"
)

// RR is a parsed resource record. RDATA is decoded into a typed zone.RDATA
// when the type is supported, otherwise kept as RawRDATA.
type RR struct {
	Name  zone.Name
	Type  zone.Type
	Class uint16
	TTL   uint32
	RDATA zone.RDATA
}

// RawRDATA preserves unrecognized RDATA verbatim so the codec can round-trip
// records the domain model does not validate.
type RawRDATA struct {
	TypeCode zone.Type
	Bytes    []byte
}

func (r RawRDATA) Type() zone.Type { return r.TypeCode }
func (r RawRDATA) Equal(o zone.RDATA) bool {
	v, ok := o.(RawRDATA)
	return ok && r.TypeCode == v.TypeCode && string(r.Bytes) == string(v.Bytes)
}
func (r RawRDATA) Canonical() []byte { return append([]byte(nil), r.Bytes...) }

// EncodeRR writes an RR using compressed names for the owner and any names in
// RDATA (NS/CNAME/SOA may be compressed in the wire form). The RDATA length is
// computed from the encoded RDATA. Returns the extended slice.
func EncodeRR(dst []byte, rr RR, table map[string]int) []byte {
	nameStart := len(dst)
	dst = EncodeCompressedName(dst, rr.Name, table)
	dst = binary.BigEndian.AppendUint16(dst, uint16(rr.Type))
	dst = binary.BigEndian.AppendUint16(dst, rr.Class)
	dst = binary.BigEndian.AppendUint32(dst, rr.TTL)
	rdlenPos := len(dst)
	dst = append(dst, 0, 0) // placeholder for RDLENGTH
	rdStart := len(dst)
	dst = encodeRDATA(dst, rr.Type, rr.RDATA, table)
	_ = nameStart
	binary.BigEndian.PutUint16(dst[rdlenPos:], uint16(len(dst)-rdStart))
	return dst
}

// EncodeRRUncompressed writes an RR with uncompressed names throughout. This is
// the canonical form used for AXFR output and content digests.
func EncodeRRUncompressed(dst []byte, rr RR) []byte {
	dst = EncodeName(dst, rr.Name)
	dst = binary.BigEndian.AppendUint16(dst, uint16(rr.Type))
	dst = binary.BigEndian.AppendUint16(dst, rr.Class)
	dst = binary.BigEndian.AppendUint32(dst, rr.TTL)
	rdlenPos := len(dst)
	dst = append(dst, 0, 0)
	rdStart := len(dst)
	dst = encodeRDATA(dst, rr.Type, rr.RDATA, nil)
	binary.BigEndian.PutUint16(dst[rdlenPos:], uint16(len(dst)-rdStart))
	return dst
}

func encodeRDATA(dst []byte, t zone.Type, r zone.RDATA, table map[string]int) []byte {
	switch v := r.(type) {
	case zone.SOA:
		dst = writeNameField(dst, v.MName, table)
		dst = writeNameField(dst, v.RName, table)
		dst = binary.BigEndian.AppendUint32(dst, v.Serial)
		dst = binary.BigEndian.AppendUint32(dst, v.Refresh)
		dst = binary.BigEndian.AppendUint32(dst, v.Retry)
		dst = binary.BigEndian.AppendUint32(dst, v.Expire)
		dst = binary.BigEndian.AppendUint32(dst, v.Minimum)
	case zone.NS:
		dst = writeNameField(dst, v.NSDName, table)
	case zone.CNAME:
		dst = writeNameField(dst, v.Target, table)
	case zone.A:
		dst = append(dst, v.IP[:]...)
	case zone.AAAA:
		dst = append(dst, v.IP[:]...)
	case zone.TXT:
		for _, s := range v.Texts {
			if len(s) > 255 {
				s = s[:255]
			}
			dst = append(dst, byte(len(s)))
			dst = append(dst, s...)
		}
	case RawRDATA:
		dst = append(dst, v.Bytes...)
	default:
		// Unknown typed RDATA: emit nothing; RDLENGTH will be 0.
	}
	return dst
}

// writeNameField writes a name into RDATA, using compression only when a table
// is supplied (message body). Canonical/AXFR encoding passes nil to force
// uncompressed form, which is required for RDATA names.
func writeNameField(dst []byte, n zone.Name, table map[string]int) []byte {
	if table != nil {
		return EncodeCompressedName(dst, n, table)
	}
	return EncodeName(dst, n)
}

// DecodeRR reads an RR from msg at off. The owner name and any names in RDATA
// are decoded with compression support. If RDLENGTH is inconsistent with the
// packet boundary a truncation error is returned; the offset after the record
// is always returned on success.
func DecodeRR(msg []byte, off int) (RR, int, error) {
	name, off, err := DecodeName(msg, off)
	if err != nil {
		return RR{}, off, err
	}
	if off+10 > len(msg) {
		return RR{}, off, fmt.Errorf("%w: RR fixed fields truncated at %d", ErrTruncated, off)
	}
	t := zone.Type(binary.BigEndian.Uint16(msg[off:]))
	class := binary.BigEndian.Uint16(msg[off+2:])
	ttl := binary.BigEndian.Uint32(msg[off+4:])
	rdlen := binary.BigEndian.Uint16(msg[off+8:])
	off += 10
	if int(rdlen) > len(msg)-off {
		return RR{}, off, fmt.Errorf("%w: RDLENGTH %d exceeds packet at %d", ErrTruncated, rdlen, off)
	}
	rdataEnd := off + int(rdlen)
	rdata, err := decodeRDATA(msg, off, rdataEnd, t)
	if err != nil {
		return RR{}, off, err
	}
	return RR{Name: name, Type: t, Class: class, TTL: ttl, RDATA: rdata}, rdataEnd, nil
}

func decodeRDATA(msg []byte, start, end int, t zone.Type) (zone.RDATA, error) {
	// rdataView is the slice of bytes belonging to this RDATA. Names inside
	// RDATA may still use compression pointers that point elsewhere in msg, so
	// we pass the full msg to DecodeName but bound the starting offset to
	// [start,end).
	switch t {
	case zone.TypeSOA:
		mname, p, err := DecodeName(msg, start)
		if err != nil {
			return nil, err
		}
		if p > end {
			return nil, fmt.Errorf("%w: SOA MNAME extends past RDLENGTH", ErrTruncated)
		}
		rname, p2, err := DecodeName(msg, p)
		if err != nil {
			return nil, err
		}
		if p2 > end {
			return nil, fmt.Errorf("%w: SOA RNAME extends past RDLENGTH", ErrTruncated)
		}
		if end-p2 < 20 {
			return nil, fmt.Errorf("%w: SOA fixed fields truncated", ErrTruncated)
		}
		if end-p2 > 20 {
			return nil, fmt.Errorf("%w: SOA RDATA trailing bytes", ErrTruncated)
		}
		return zone.SOA{
			MName:   mname,
			RName:   rname,
			Serial:  binary.BigEndian.Uint32(msg[p2:]),
			Refresh: binary.BigEndian.Uint32(msg[p2+4:]),
			Retry:   binary.BigEndian.Uint32(msg[p2+8:]),
			Expire:  binary.BigEndian.Uint32(msg[p2+12:]),
			Minimum: binary.BigEndian.Uint32(msg[p2+16:]),
		}, nil
	case zone.TypeNS:
		n, p, err := DecodeName(msg, start)
		if err != nil {
			return nil, err
		}
		if p != end {
			return nil, fmt.Errorf("%w: NS RDATA trailing bytes", ErrTruncated)
		}
		return zone.NS{NSDName: n}, nil
	case zone.TypeCNAME:
		n, p, err := DecodeName(msg, start)
		if err != nil {
			return nil, err
		}
		if p != end {
			return nil, fmt.Errorf("%w: CNAME RDATA trailing bytes", ErrTruncated)
		}
		return zone.CNAME{Target: n}, nil
	case zone.TypeA:
		if end-start != 4 {
			return nil, fmt.Errorf("%w: A RDATA length %d != 4", ErrTruncated, end-start)
		}
		var ip [4]byte
		copy(ip[:], msg[start:end])
		return zone.A{IP: ip}, nil
	case zone.TypeAAAA:
		if end-start != 16 {
			return nil, fmt.Errorf("%w: AAAA RDATA length %d != 16", ErrTruncated, end-start)
		}
		var ip [16]byte
		copy(ip[:], msg[start:end])
		return zone.AAAA{IP: ip}, nil
	case zone.TypeTXT:
		var texts []string
		p := start
		for p < end {
			l := int(msg[p])
			p++
			if p+l > end {
				return nil, fmt.Errorf("%w: TXT character-string truncated", ErrTruncated)
			}
			texts = append(texts, string(msg[p:p+l]))
			p += l
		}
		return zone.TXT{Texts: texts}, nil
	default:
		return RawRDATA{TypeCode: t, Bytes: append([]byte(nil), msg[start:end]...)}, nil
	}
}
