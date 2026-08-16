package dnscodec

import (
	"errors"
	"reflect"
	"testing"

	"intranet-dns-zone-release-coordinator/internal/zone"
)

func TestDecodeMessagePreservesQuestions(t *testing.T) {
	query := Message{
		Header: Header{ID: 0x1234},
		Question: []Question{{
			Name: zone.MustNormalizeName("www.example.com"), Type: zone.TypeA, Class: ClassIN,
		}},
	}
	withRecords := Message{
		Header: Header{ID: 0x5678},
		Question: []Question{
			{Name: zone.MustNormalizeName("example.com"), Type: zone.TypeSOA, Class: ClassIN},
			{Name: zone.MustNormalizeName("www.example.com"), Type: zone.TypeAAAA, Class: ClassIN},
		},
		Answers: []RR{{
			Name: zone.MustNormalizeName("www.example.com"), Type: zone.TypeA, Class: ClassIN,
			TTL: 300, RDATA: zone.A{IP: [4]byte{192, 0, 2, 1}},
		}},
		Authority: []RR{{
			Name: zone.MustNormalizeName("example.com"), Type: zone.TypeNS, Class: ClassIN,
			TTL: 300, RDATA: zone.NS{NSDName: zone.MustNormalizeName("ns1.example.com")},
		}},
		Additional: []RR{{
			Name: zone.MustNormalizeName("ns1.example.com"), Type: zone.TypeA, Class: ClassIN,
			TTL: 300, RDATA: zone.A{IP: [4]byte{192, 0, 2, 53}},
		}},
	}

	for _, tc := range []struct {
		name string
		msg  Message
	}{
		{name: "query only", msg: query},
		{name: "with resource records", msg: withRecords},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeMessage(EncodeMessage(tc.msg))
			if err != nil {
				t.Fatalf("DecodeMessage() error = %v", err)
			}
			if got.Header.QDCount != uint16(len(tc.msg.Question)) {
				t.Fatalf("QDCount = %d, want %d", got.Header.QDCount, len(tc.msg.Question))
			}
			if !reflect.DeepEqual(got.Question, tc.msg.Question) {
				t.Errorf("Question = %#v, want %#v", got.Question, tc.msg.Question)
			}
			if !reflect.DeepEqual(got.Answers, tc.msg.Answers) {
				t.Errorf("Answers = %#v, want %#v", got.Answers, tc.msg.Answers)
			}
			if !reflect.DeepEqual(got.Authority, tc.msg.Authority) {
				t.Errorf("Authority = %#v, want %#v", got.Authority, tc.msg.Authority)
			}
			if !reflect.DeepEqual(got.Additional, tc.msg.Additional) {
				t.Errorf("Additional = %#v, want %#v", got.Additional, tc.msg.Additional)
			}
		})
	}

	t.Run("rejects trailing data", func(t *testing.T) {
		wire := append(EncodeMessage(query), 0xff)
		if _, err := DecodeMessage(wire); !errors.Is(err, ErrTruncated) {
			t.Fatalf("DecodeMessage() error = %v, want ErrTruncated", err)
		}
	})
}
