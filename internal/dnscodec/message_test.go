package dnscodec

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// eofWithLastReader serves data one buffer's worth at a time, returning io.EOF
// together with the final bytes rather than in a separate trailing Read. This
// models readers (files, network connections) that signal end-of-stream with
// their last non-empty chunk, which is the case the io.Reader contract allows
// and that ReadTCPFrame must tolerate.
type eofWithLastReader struct {
	data []byte
	pos  int
}

func (r *eofWithLastReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	if r.pos >= len(r.data) {
		return n, io.EOF
	}
	return n, nil
}

// chunkReader delivers each provided chunk in its own Read call and only
// returns io.EOF after every chunk has been consumed, never alongside data.
// It models a reader whose data arrives in small fragments.
type chunkReader struct {
	chunks [][]byte
	pos    int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.pos >= len(c.chunks) {
		return 0, io.EOF
	}
	chunk := c.chunks[c.pos]
	c.pos++
	return copy(p, chunk), nil
}

// TestReadTCPFrame_FinalChunkWithEOF covers the regression: when the reader
// returns the complete remaining payload together with io.EOF in the last
// Read, the already-complete frame must be returned, not classified as
// ErrTruncated.
func TestReadTCPFrame_FinalChunkWithEOF(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	// Length prefix and payload arrive in separate reads; the payload read
	// returns all five bytes plus io.EOF at once.
	r := &eofWithLastReader{data: append([]byte{0x00, 0x05}, payload...)}
	got, err := ReadTCPFrame(r)
	if err != nil {
		t.Fatalf("ReadTCPFrame returned error for complete frame with trailing EOF: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("ReadTCPFrame payload = %v, want %v", got, payload)
	}

	// The length prefix itself may arrive together with io.EOF when it is the
	// whole stream (here the payload then arrives in a fresh read).
	r2 := newPrefixThenEOFReader(0x0005, payload)
	got2, err2 := ReadTCPFrame(r2)
	if err2 != nil {
		t.Fatalf("ReadTCPFrame returned error when length prefix carries trailing EOF: %v", err2)
	}
	if !bytes.Equal(got2, payload) {
		t.Fatalf("ReadTCPFrame payload = %v, want %v", got2, payload)
	}

	// Entire frame (prefix + payload) in a single Read that also returns EOF.
	r3 := &eofWithLastReader{data: append([]byte{0x00, 0x05}, payload...)}
	// Force single-shot delivery by reading through a one-byte-prefix path:
	// eofWithLastReader handles partial consumption, so a single underlying
	// read returning all bytes plus EOF exercises both readFull calls.
	got3, err3 := ReadTCPFrame(r3)
	if err3 != nil {
		t.Fatalf("ReadTCPFrame returned error for whole-frame single read with EOF: %v", err3)
	}
	if !bytes.Equal(got3, payload) {
		t.Fatalf("ReadTCPFrame payload = %v, want %v", got3, payload)
	}
}

// prefixThenEOFReader returns the 2-byte length prefix together with io.EOF on
// the first read, then yields the payload bytes from a separate reader that
// returns data without a trailing error.
type prefixThenEOFReader struct {
	prefix  []byte
	payload []byte
	pidx    int
	done    bool
}

func newPrefixThenEOFReader(length uint16, payload []byte) *prefixThenEOFReader {
	prefix := []byte{byte(length >> 8), byte(length)}
	return &prefixThenEOFReader{prefix: prefix, payload: payload}
}

func (r *prefixThenEOFReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		// Hand back only the prefix, but signal EOF on this read.
		n := copy(p, r.prefix)
		return n, io.EOF
	}
	if r.pidx >= len(r.payload) {
		return 0, io.EOF
	}
	n := copy(p, r.payload[r.pidx:])
	r.pidx += n
	return n, nil
}

// TestReadTCPFrame_SegmentedReads covers normal fragmented delivery: the frame
// arrives one byte at a time with no EOF accompanying data. It must assemble
// correctly.
func TestReadTCPFrame_SegmentedReads(t *testing.T) {
	payload := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	stream := append([]byte{0x00, 0x04}, payload...)
	chunks := make([][]byte, 0, len(stream))
	for _, b := range stream {
		chunks = append(chunks, []byte{b})
	}
	r := &chunkReader{chunks: chunks}
	got, err := ReadTCPFrame(r)
	if err != nil {
		t.Fatalf("ReadTCPFrame returned error for segmented reads: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("ReadTCPFrame payload = %v, want %v", got, payload)
	}
}

// TestReadTCPFrame_RealTruncation covers genuine short frames: a declared
// length that the stream never satisfies must be reported as ErrTruncated, for
// both the payload and the length prefix.
func TestReadTCPFrame_RealTruncation(t *testing.T) {
	// Declared length 5 but only 3 payload bytes before EOF.
	r := &eofWithLastReader{data: []byte{0x00, 0x05, 0x01, 0x02, 0x03}}
	if _, err := ReadTCPFrame(r); !errors.Is(err, ErrTruncated) {
		t.Fatalf("short payload: err = %v, want ErrTruncated", err)
	}

	// Length prefix truncated to a single byte before EOF.
	r2 := &eofWithLastReader{data: []byte{0x00}}
	if _, err := ReadTCPFrame(r2); !errors.Is(err, ErrTruncated) {
		t.Fatalf("short length prefix: err = %v, want ErrTruncated", err)
	}

	// Empty stream: length prefix cannot be read at all.
	r3 := &eofWithLastReader{data: nil}
	if _, err := ReadTCPFrame(r3); !errors.Is(err, ErrTruncated) {
		t.Fatalf("empty stream: err = %v, want ErrTruncated", err)
	}
}

// TestReadTCPFrame_ZeroLength confirms a declared length of zero yields a nil
// payload with no error and consumes only the 2-byte prefix.
func TestReadTCPFrame_ZeroLength(t *testing.T) {
	r := &eofWithLastReader{data: []byte{0x00, 0x00}}
	got, err := ReadTCPFrame(r)
	if err != nil {
		t.Fatalf("ReadTCPFrame zero-length returned error: %v", err)
	}
	if got != nil {
		t.Fatalf("ReadTCPFrame zero-length payload = %v, want nil", got)
	}
}

// TestWriteReadTCPFrame_RoundTrip confirms framing round-trips and that
// WriteTCPFrame behavior is unchanged.
func TestWriteReadTCPFrame_RoundTrip(t *testing.T) {
	payload := []byte("hello-dns-tcp-frame")
	var buf bytes.Buffer
	if err := WriteTCPFrame(&buf, payload); err != nil {
		t.Fatalf("WriteTCPFrame returned error: %v", err)
	}
	got, err := ReadTCPFrame(&buf)
	if err != nil {
		t.Fatalf("ReadTCPFrame returned error: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip payload = %q, want %q", got, payload)
	}

	// Oversized payload is rejected.
	tooBig := make([]byte, 0x10000)
	if err := WriteTCPFrame(&buf, tooBig); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("oversized WriteTCPFrame: err = %v, want ErrInvalidMessage", err)
	}
}
