package dnscodec

import (
	"errors"
	"io"
	"reflect"
	"testing"
)

type readResult struct {
	data []byte
	err  error
}

type resultReader struct {
	results []readResult
}

func (r *resultReader) Read(p []byte) (int, error) {
	result := r.results[0]
	r.results = r.results[1:]
	return copy(p, result.data), result.err
}

func TestReadTCPFrameReadBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		results     []readResult
		want        []byte
		wantErr     error
		wantNilData bool
	}{
		{
			name: "final payload data with EOF",
			results: []readResult{
				{data: []byte{0, 3}},
				{data: []byte("dns"), err: io.EOF},
			},
			want: []byte("dns"),
		},
		{
			name: "fragmented frame",
			results: []readResult{
				{data: []byte{0}},
				{data: []byte{3}},
				{data: []byte("d")},
				{data: []byte("ns")},
			},
			want: []byte("dns"),
		},
		{
			name: "zero length with final prefix EOF",
			results: []readResult{
				{data: []byte{0, 0}, err: io.EOF},
			},
			wantNilData: true,
		},
		{
			name: "truncated payload",
			results: []readResult{
				{data: []byte{0, 3}},
				{data: []byte("dn"), err: io.EOF},
			},
			wantErr:     ErrTruncated,
			wantNilData: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadTCPFrame(&resultReader{results: tt.results})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ReadTCPFrame() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantNilData {
				if got != nil {
					t.Fatalf("ReadTCPFrame() data = %v, want nil", got)
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ReadTCPFrame() data = %v, want %v", got, tt.want)
			}
		})
	}
}
