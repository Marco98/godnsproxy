package routeros

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	routeros "github.com/go-routeros/routeros/v3"
	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

var errRosAddressNotFound = errors.New("no existing address-list record found")

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
	// Handle CNAMEs
	cnames := make(map[string]string)
	for _, v := range resp.Answer {
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
	hadEffect := false
	for _, v := range resp.Answer {
		if v.Header().Rrtype != dns.TypeA {
			continue
		}
		va, ok := v.(*dns.A)
		if !ok {
			continue
		}
		nttl := uint(va.Hdr.Ttl) + h.GraceTTL
		name := strings.TrimSuffix(va.Hdr.Name, ".")
		for _, fqdn := range h.matchFqdns {
			// Direct match
			if fqdn == name || (strings.HasPrefix(fqdn, "*.") && strings.HasSuffix(name, strings.TrimPrefix(fqdn, "*"))) {
				if h.addAddressList(fqdn, va.A.String(), nttl) {
					hadEffect = true
				}
			}
			// CNAME match
			cn, ok := cnames[name]
			if ok && fqdn == cn || (strings.HasPrefix(fqdn, "*.") && strings.HasSuffix(cn, strings.TrimPrefix(fqdn, "*"))) {
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
	h.clientLock.Lock()
	if c, err := h.getClient(); err == nil {
		if _, err := c.Run("/ip/dns/cache/flush"); err != nil {
			slog.Error("error flushing dns cache")
		}
	}
	h.clientLock.Unlock()
	for {
		h.updateMatchFqdns()
		time.Sleep(5 * time.Second)
	}
}

func (h *Hook) updateMatchFqdns() {
	c, err := h.getClient()
	if err != nil {
		slog.Error("error getting client", "err", err)
		return
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
		return
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
	if err := h.addAddressListRecord(name, ip, ttl); err != nil {
		if strings.Contains(err.Error(), "already have such entry") {
			if err := h.refreshAddressList(name, ip, ttl); err != nil {
				if errors.Is(err, errRosAddressNotFound) {
					if err := h.addAddressListRecord(name, ip, ttl); err != nil {
						slog.Error("error adding rec", "err", err)
					}
				} else {
					slog.Error("error refreshing rec", "err", err)
				}
			}
		} else {
			slog.Error("error adding rec", "err", err)
		}
		return false
	}
	h.cacheSet(name, ip, ttl)
	return true
}

func (h *Hook) addAddressListRecord(name, ip string, ttl uint) error {
	c, err := h.getClient()
	if err != nil {
		return fmt.Errorf("error getting client: %w", err)
	}
	h.clientLock.Lock()
	defer h.clientLock.Unlock()
	_, err = c.Run(
		"/ip/firewall/address-list/add",
		"dynamic=yes",
		fmt.Sprintf("=list=%s", name),
		fmt.Sprintf("=address=%s", ip),
		fmt.Sprintf("=timeout=%d", ttl),
	)
	if err != nil {
		return err
	}
	slog.Info("address-list added", "name", name, "ip", ip, "ttl", ttl)
	return nil
}

func (h *Hook) refreshAddressList(name, ip string, ttl uint) error {
	c, err := h.getClient()
	if err != nil {
		return err
	}
	h.clientLock.Lock()
	res, err := c.Run(
		"/ip/firewall/address-list/print",
		fmt.Sprintf("?address=%s", ip),
		fmt.Sprintf("?list=%s", name),
		"?dynamic=yes",
		"=.proplist=.id",
	)
	h.clientLock.Unlock()
	if err != nil {
		return err
	}
	if len(res.Re) < 1 {
		return errRosAddressNotFound
	}
	h.clientLock.Lock()
	_, err = c.Run(
		"/ip/firewall/address-list/set",
		fmt.Sprintf("=.id=%s", res.Re[0].Map[".id"]),
		fmt.Sprintf("=timeout=%d", ttl),
	)
	h.clientLock.Unlock()
	slog.Debug("address-list record refreshed", "name", name, "ip", ip, "ttl", ttl)
	return err
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
	h.cache[fmt.Sprintf("%s|%s", name, ip)] = time.Now().Add(time.Duration(ttl-h.GraceTTL) * time.Second) // nolint:gosec
}
