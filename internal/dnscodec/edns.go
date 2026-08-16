package dnscodec

import (
	"encoding/binary"
	"fmt"

	"intranet-dns-zone-release-coordinator/internal/zone"
)

// EDNS0 option codes used privately by the coordinator. They are in the
// "private use" range and only need to be self-consistent across the data and
// management planes.
const (
	// OptionUpdateMeta carries update metadata (view, operation ID, expected
	// draft revision, base active serial) on a DNS UPDATE message.
	OptionUpdateMeta uint16 = 0xFF01
	// OptionControl carries a management command (seal/publish/abandon/retire)
	// over the local DNS-over-TCP control channel.
	OptionControl uint16 = 0xFF02
)

// UpdateMeta is the metadata carried in the private EDNS option on UPDATE
// messages.
type UpdateMeta struct {
	View              string
	OpID              string
	ExpectedRevision  uint64
	BaseActiveSerial  uint32
}

// ControlCode identifies a management command.
type ControlCode uint8

const (
	CtrlSeal    ControlCode = 1
	CtrlPublish ControlCode = 2
	CtrlAbandon ControlCode = 3
	CtrlRetire  ControlCode = 4
)

// ControlMeta carries a management command's parameters.
type ControlMeta struct {
	Code           ControlCode
	View           string
	Zone           zone.Name
	Serial         uint32 // target serial for retire
	OpID           string
	BaseActiveSerial uint32 // for publish preconditions
}

// EncodeOPT encodes an OPT pseudo-RR (EDNS0) carrying the given option code/data.
// The owner name is root, class carries a max UDP payload size, and the TTL is
// the extended RCODE/flags (kept zero here).
func EncodeOPT(dst []byte, optCode uint16, optData []byte, udpPayload uint16) []byte {
	dst = append(dst, 0) // root owner
	dst = binary.BigEndian.AppendUint16(dst, uint16(zone.TypeOPT))
	dst = binary.BigEndian.AppendUint16(dst, udpPayload) // class = UDP payload size
	dst = binary.BigEndian.AppendUint32(dst, 0)          // extended RCODE + flags
	rdlenPos := len(dst)
	dst = append(dst, 0, 0)
	rdStart := len(dst)
	// option: code(2) + length(2) + data
	dst = binary.BigEndian.AppendUint16(dst, optCode)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(optData)))
	dst = append(dst, optData...)
	binary.BigEndian.PutUint16(dst[rdlenPos:], uint16(len(dst)-rdStart))
	return dst
}

// FindOPT locates and parses the first OPT RR in the additional section,
// returning nil if none is present.
func FindOPT(m Message) *RR {
	for i := range m.Additional {
		if m.Additional[i].Type == zone.TypeOPT {
			return &m.Additional[i]
		}
	}
	return nil
}

// FindEDNSOption returns the data of the first EDNS option matching code in the
// OPT RR, or nil if absent.
func FindEDNSOption(opt *RR, code uint16) []byte {
	if opt == nil {
		return nil
	}
	raw, ok := opt.RDATA.(RawRDATA)
	if !ok {
		return nil
	}
	p := 0
	for p+4 <= len(raw.Bytes) {
		c := binary.BigEndian.Uint16(raw.Bytes[p:])
		l := binary.BigEndian.Uint16(raw.Bytes[p+2:])
		p += 4
		if int(l) > len(raw.Bytes)-p {
			return nil
		}
		if c == code {
			return raw.Bytes[p : p+int(l)]
		}
		p += int(l)
	}
	return nil
}

// EncodeUpdateMetaOption builds the OPT additional RR for an UPDATE message.
func EncodeUpdateMetaOption(meta UpdateMeta) RR {
	data := encodeUpdateMeta(meta)
	return RR{Type: zone.TypeOPT, Class: 4096, RDATA: RawRDATA{TypeCode: zone.TypeOPT, Bytes: encodeEDNSOption(OptionUpdateMeta, data)}}
}

func encodeEDNSOption(code uint16, data []byte) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint16(b, code)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	b = append(b, data...)
	return b
}

// encodeUpdateMeta: viewLen(1) + view + opIDLen(1) + opID + expectedRev(8) + baseSerial(4)
func encodeUpdateMeta(m UpdateMeta) []byte {
	var b []byte
	v := []byte(m.View)
	if len(v) > 255 {
		v = v[:255]
	}
	b = append(b, byte(len(v)))
	b = append(b, v...)
	o := []byte(m.OpID)
	if len(o) > 255 {
		o = o[:255]
	}
	b = append(b, byte(len(o)))
	b = append(b, o...)
	b = binary.BigEndian.AppendUint64(b, m.ExpectedRevision)
	b = binary.BigEndian.AppendUint32(b, m.BaseActiveSerial)
	return b
}

// DecodeUpdateMeta parses the private UPDATE metadata option from an OPT RR.
func DecodeUpdateMeta(opt *RR) (UpdateMeta, error) {
	data := FindEDNSOption(opt, OptionUpdateMeta)
	if data == nil {
		return UpdateMeta{}, fmt.Errorf("%w: no update-meta option", ErrInvalidMessage)
	}
	return decodeUpdateMeta(data)
}

func decodeUpdateMeta(data []byte) (UpdateMeta, error) {
	var m UpdateMeta
	p := 0
	if p >= len(data) {
		return m, fmt.Errorf("%w: update-meta view length missing", ErrTruncated)
	}
	vl := int(data[p])
	p++
	if p+vl > len(data) {
		return m, fmt.Errorf("%w: update-meta view truncated", ErrTruncated)
	}
	m.View = string(data[p : p+vl])
	p += vl
	if p >= len(data) {
		return m, fmt.Errorf("%w: update-meta opid length missing", ErrTruncated)
	}
	ol := int(data[p])
	p++
	if p+ol > len(data) {
		return m, fmt.Errorf("%w: update-meta opid truncated", ErrTruncated)
	}
	m.OpID = string(data[p : p+ol])
	p += ol
	if p+12 > len(data) {
		return m, fmt.Errorf("%w: update-meta tail truncated", ErrTruncated)
	}
	m.ExpectedRevision = binary.BigEndian.Uint64(data[p:])
	m.BaseActiveSerial = binary.BigEndian.Uint32(data[p+8:])
	return m, nil
}

// EncodeControlOption builds the OPT additional RR for a control message.
func EncodeControlOption(meta ControlMeta) RR {
	data := encodeControlMeta(meta)
	return RR{Type: zone.TypeOPT, Class: 4096, RDATA: RawRDATA{TypeCode: zone.TypeOPT, Bytes: encodeEDNSOption(OptionControl, data)}}
}

// encodeControlMeta: code(1)+viewLen(1)+view+zoneLen(1)+zone+serial(4)+opIDLen(1)+opID+base(4)
func encodeControlMeta(c ControlMeta) []byte {
	var b []byte
	b = append(b, byte(c.Code))
	v := []byte(c.View)
	if len(v) > 255 {
		v = v[:255]
	}
	b = append(b, byte(len(v)))
	b = append(b, v...)
	z := []byte(string(c.Zone))
	if len(z) > 255 {
		z = z[:255]
	}
	b = append(b, byte(len(z)))
	b = append(b, z...)
	b = binary.BigEndian.AppendUint32(b, c.Serial)
	o := []byte(c.OpID)
	if len(o) > 255 {
		o = o[:255]
	}
	b = append(b, byte(len(o)))
	b = append(b, o...)
	b = binary.BigEndian.AppendUint32(b, c.BaseActiveSerial)
	return b
}

// DecodeControlMeta parses the private control metadata option from an OPT RR.
func DecodeControlMeta(opt *RR) (ControlMeta, error) {
	data := FindEDNSOption(opt, OptionControl)
	if data == nil {
		return ControlMeta{}, fmt.Errorf("%w: no control option", ErrInvalidMessage)
	}
	var c ControlMeta
	p := 0
	if p >= len(data) {
		return c, fmt.Errorf("%w: control code missing", ErrTruncated)
	}
	c.Code = ControlCode(data[p])
	p++
	if p >= len(data) {
		return c, fmt.Errorf("%w: control view length missing", ErrTruncated)
	}
	vl := int(data[p])
	p++
	if p+vl > len(data) {
		return c, fmt.Errorf("%w: control view truncated", ErrTruncated)
	}
	c.View = string(data[p : p+vl])
	p += vl
	if p >= len(data) {
		return c, fmt.Errorf("%w: control zone length missing", ErrTruncated)
	}
	zl := int(data[p])
	p++
	if p+zl > len(data) {
		return c, fmt.Errorf("%w: control zone truncated", ErrTruncated)
	}
	zn, err := zone.NormalizeName(string(data[p : p+zl]))
	if err != nil {
		return c, fmt.Errorf("%w: control zone: %v", ErrInvalidMessage, err)
	}
	c.Zone = zn
	p += zl
	if p+4 > len(data) {
		return c, fmt.Errorf("%w: control serial truncated", ErrTruncated)
	}
	c.Serial = binary.BigEndian.Uint32(data[p:])
	p += 4
	if p >= len(data) {
		return c, fmt.Errorf("%w: control opid length missing", ErrTruncated)
	}
	ol := int(data[p])
	p++
	if p+ol > len(data) {
		return c, fmt.Errorf("%w: control opid truncated", ErrTruncated)
	}
	c.OpID = string(data[p : p+ol])
	p += ol
	if p+4 > len(data) {
		return c, fmt.Errorf("%w: control base serial truncated", ErrTruncated)
	}
	c.BaseActiveSerial = binary.BigEndian.Uint32(data[p:])
	return c, nil
}
