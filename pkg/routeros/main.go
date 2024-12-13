package routeros

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	routeros "github.com/go-routeros/routeros/v3"
	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

type Hook struct {
	Address        string
	Username       string
	Password       string
	GraceTTL       uint
	PropagateDelay uint
	client         *routeros.Client
	clientLock     sync.Mutex
	matchFqdns     []string
	cache          map[string]time.Time
	cacheLock      sync.RWMutex
}

func (h *Hook) Hook(resp *dns.Msg) {
	hadEffect := false
	for _, v := range resp.Answer {
		if v.Header().Rrtype != dns.TypeA {
			return
		}
		va := v.(*dns.A)
		nttl := uint(va.Hdr.Ttl) + h.GraceTTL
		name := strings.TrimSuffix(va.Hdr.Name, ".")
		for _, fqdn := range h.matchFqdns {
			if fqdn == name {
				if h.addAddressList(fqdn, va.A.String(), nttl) {
					hadEffect = true
				}
			} else if strings.HasPrefix(fqdn, "*.") && strings.HasSuffix(name, strings.TrimPrefix(fqdn, "*")) {
				if h.addAddressList(fqdn, va.A.String(), nttl) {
					hadEffect = true
				}
			}
		}
	}
	if hadEffect {
		time.Sleep(time.Duration(h.PropagateDelay) * time.Millisecond) //nolint:gosec
	}
}

func (h *Hook) Daemon() {
	first := true
	for {
		if !first {
			time.Sleep(5 * time.Second)
		}
		first = false
		c, err := h.getClient()
		if err != nil {
			slog.Error("error getting client", "err", err)
			continue
		}
		h.clientLock.Lock()
		resp, err := c.Run(
			"/ip/firewall/filter/print",
			"?disabled=false",
			"?dst-address-list",
			"=.proplist=dst-address-list",
		)
		h.clientLock.Unlock()
		if err != nil {
			slog.Error("error fetching rules", "err", err)
			continue
		}
		fqdns := make([]string, 0)
		for _, v := range resp.Re {
			fqdn := v.Map["dst-address-list"]
			isWC := strings.HasPrefix(fqdn, "*.")
			fqdn, err = idna.Lookup.ToASCII(strings.TrimPrefix(fqdn, "*."))
			if err != nil {
				continue
			}
			if isWC {
				fqdn = fmt.Sprintf("*.%s", fqdn)
			}
			fqdns = append(fqdns, fqdn)
		}
		slog.Debug("fetched matchFqdns from firewall", "count", len(fqdns), "list", fqdns)
		h.matchFqdns = fqdns
	}
}

func (h *Hook) getClient() (*routeros.Client, error) {
	if h.client != nil {
		return h.client, nil
	}
	c, err := routeros.DialTimeout(h.Address, h.Username, h.Password, 3*time.Second)
	if err != nil {
		return nil, err
	}
	h.client = c
	return c, nil
}

func (h *Hook) addAddressList(name, ip string, ttl uint) bool {
	if h.cacheExists(name, ip) {
		return false
	}
	c, err := h.getClient()
	if err != nil {
		slog.Error("error getting client", "err", err)
		return false
	}
	slog.Info("adding rec", "name", name, "ip", ip, "ttl", ttl)
	h.clientLock.Lock()
	_, err = c.Run(
		"/ip/firewall/address-list/add",
		"dynamic=yes",
		fmt.Sprintf("=list=%s", name),
		fmt.Sprintf("=address=%s", ip),
		fmt.Sprintf("=timeout=%d", ttl),
	)
	h.clientLock.Unlock()
	if err != nil && !strings.Contains(err.Error(), "already have such entry") {
		slog.Error("error adding rec", "err", err)
		return false
	}
	h.cacheSet(name, ip, ttl)
	return true
}

func (h *Hook) cacheExists(name, ip string) bool {
	h.cacheLock.RLock()
	defer h.cacheLock.RUnlock()
	ttl, ok := h.cache[fmt.Sprintf("%s|%s", name, ip)]
	if !ok {
		return false
	}
	return ttl.After(time.Now())
}

func (h *Hook) cacheSet(name, ip string, ttl uint) {
	h.cacheLock.Lock()
	defer h.cacheLock.Unlock()
	if h.cache == nil {
		h.cache = make(map[string]time.Time)
	}
	h.cache[fmt.Sprintf("%s|%s", name, ip)] = time.Now().Add(time.Duration(ttl) * time.Second) // nolint:gosec
}
