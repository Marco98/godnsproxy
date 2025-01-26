package dnsmatch_test

import (
	"net"
	"testing"

	"github.com/Marco98/godnsproxy/pkg/dnsmatch"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestMatching(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		answer     []dns.RR
		matchFqdns []string
		results    []dnsmatch.MatchResult
	}{
		{
			name:       "Simple Match",
			matchFqdns: []string{"google.com"},
			answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Rrtype: dns.TypeA,
						Name:   "google.com.",
						Ttl:    300,
					},
					A: net.IPv4(123, 123, 123, 123),
				},
			},
			results: []dnsmatch.MatchResult{
				{
					Fqdn:      "google.com",
					IPAddress: net.IPv4(123, 123, 123, 123),
					TTL:       300,
				},
			},
		},
		{
			name:       "Simple Mismatch",
			matchFqdns: []string{"facebook.com"},
			answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Rrtype: dns.TypeA,
						Name:   "google.com.",
						Ttl:    300,
					},
					A: net.IPv4(123, 123, 123, 123),
				},
			},
			results: []dnsmatch.MatchResult{},
		},
		{
			name:       "Wildcard Match",
			matchFqdns: []string{"*.google.com"},
			answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Rrtype: dns.TypeA,
						Name:   "www.google.com.",
						Ttl:    300,
					},
					A: net.IPv4(123, 123, 123, 123),
				},
			},
			results: []dnsmatch.MatchResult{
				{
					Fqdn:      "*.google.com",
					IPAddress: net.IPv4(123, 123, 123, 123),
					TTL:       300,
				},
			},
		},
		{
			name:       "Wildcard Mismatch",
			matchFqdns: []string{"*.google.com"},
			answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Rrtype: dns.TypeA,
						Name:   "google.com.",
						Ttl:    300,
					},
					A: net.IPv4(123, 123, 123, 123),
				},
			},
			results: []dnsmatch.MatchResult{},
		},
		{
			name:       "CNAME Match",
			matchFqdns: []string{"google.com"},
			answer: []dns.RR{
				&dns.CNAME{
					Hdr: dns.RR_Header{
						Rrtype: dns.TypeCNAME,
						Name:   "google.com.",
					},
					Target: "www.google.com.",
				},
				&dns.A{
					Hdr: dns.RR_Header{
						Rrtype: dns.TypeA,
						Name:   "www.google.com.",
						Ttl:    300,
					},
					A: net.IPv4(123, 123, 123, 123),
				},
			},
			results: []dnsmatch.MatchResult{
				{
					Fqdn:      "google.com",
					IPAddress: net.IPv4(123, 123, 123, 123),
					TTL:       300,
				},
			},
		},
		{
			name:       "Nested CNAME Match",
			matchFqdns: []string{"www.google.com"},
			answer: []dns.RR{
				&dns.CNAME{
					Hdr: dns.RR_Header{
						Rrtype: dns.TypeCNAME,
						Name:   "www.google.com.",
					},
					Target: "cname1.google.com.",
				},
				&dns.CNAME{
					Hdr: dns.RR_Header{
						Rrtype: dns.TypeCNAME,
						Name:   "cname1.google.com.",
					},
					Target: "cname2.google.com.",
				},
				&dns.A{
					Hdr: dns.RR_Header{
						Rrtype: dns.TypeA,
						Name:   "cname2.google.com.",
						Ttl:    300,
					},
					A: net.IPv4(123, 123, 123, 123),
				},
			},
			results: []dnsmatch.MatchResult{
				{
					Fqdn:      "www.google.com",
					IPAddress: net.IPv4(123, 123, 123, 123),
					TTL:       300,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, test.results, dnsmatch.MatchDNS(test.answer, test.matchFqdns))
		})
	}
}
