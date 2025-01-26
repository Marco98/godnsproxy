package dnsmatch

import (
	"net"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

type MatchResult struct {
	Fqdn      string
	IPAddress net.IP
	TTL       uint32
}

func MatchDNS(answer []dns.RR, matchFqdns []string) []MatchResult {
	result := make([]MatchResult, 0)
	// Handle CNAMEs
	cnames := make(map[string]string)
	for _, v := range answer {
		if v.Header().Rrtype != dns.TypeCNAME {
			continue
		}
		cname, ok := v.(*dns.CNAME)
		if !ok {
			continue
		}
		cnames[strings.TrimSuffix(cname.Target, ".")] = strings.TrimSuffix(cname.Hdr.Name, ".")
	}
	// Handle A-Records
	for _, v := range answer {
		if v.Header().Rrtype != dns.TypeA {
			continue
		}
		va, ok := v.(*dns.A)
		if !ok {
			continue
		}
		name := strings.TrimSuffix(va.Hdr.Name, ".")
		for _, fqdn := range matchFqdns {
			// Direct match
			if fqdn == name || (strings.HasPrefix(fqdn, "*.") && strings.HasSuffix(name, strings.TrimPrefix(fqdn, "*"))) {
				result = append(result, MatchResult{
					Fqdn:      fqdn,
					IPAddress: va.A,
					TTL:       va.Hdr.Ttl,
				})
			}
			// CNAME match
			if resolveCname(cnames, name, fqdn) {
				result = append(result, MatchResult{
					Fqdn:      fqdn,
					IPAddress: va.A,
					TTL:       va.Hdr.Ttl,
				})
			}
		}
	}
	return result
}

func resolveCname(cnames map[string]string, a, matchFqdn string) bool {
	past := []string{a}
	cn, ok := cnames[a]
	for ok {
		// break on loop
		if slices.Contains(past, cn) {
			break
		}
		// direct match
		if cn == matchFqdn {
			return true
		}
		// wildcard match
		if strings.HasPrefix(matchFqdn, "*.") && strings.HasSuffix(cn, strings.TrimPrefix(matchFqdn, "*")) {
			return true
		}
		// recursive search
		past = append(past, cn)
		cn, ok = cnames[cn]
	}
	return false
}
