package routeros

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Marco98/godnsproxy/pkg/dnsmatch"
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
	hadEffect := false
	for _, v := range dnsmatch.MatchDNS(resp.Answer, h.matchFqdns) {
		if h.addAddressList(v.Fqdn, v.IPAddress.String(), uint(v.TTL)+h.GraceTTL) {
			hadEffect = true
		}
	}
	if hadEffect {
		time.Sleep(time.Duration(h.PropagateDelay) * time.Millisecond) //nolint:gosec
	}
}

func (h *Hook) Daemon() {
	if _, err := h.runClient("/ip/dns/cache/flush"); err != nil {
		slog.Error("error flushing dns cache")
	}
	for {
		h.updateMatchFqdns()
		h.cachePurge()
		time.Sleep(5 * time.Second)
	}
}

func (h *Hook) updateMatchFqdns() {
	resp, err := h.runClient(
		"/ip/firewall/filter/print",
		"?disabled=false",
		"?dst-address-list",
		"=.proplist=dst-address-list",
	)
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

func (h *Hook) runClient(sentences ...string) (*routeros.Reply, error) {
	h.clientLock.Lock()
	defer h.clientLock.Unlock()
	if h.client == nil {
		var err error
		h.client, err = routeros.DialTimeout(h.Address, h.Username, h.Password, 3*time.Second)
		if err != nil {
			return nil, fmt.Errorf("error getting client: %w", err)
		}
	}
	return h.client.Run(sentences...)
}

func (h *Hook) addAddressList(name, ip string, ttl uint) bool {
	if h.cacheExists(name, ip) {
		return false
	}
	var err error
	for range 3 {
		err = h.addAddressListRecord(name, ip, ttl)
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "already have such entry") {
			slog.Error("error adding rec", "err", err)
			return false
		}
		err = h.refreshAddressList(name, ip, ttl)
		if err == nil {
			break
		}
		if !errors.Is(err, errRosAddressNotFound) {
			slog.Error("error refreshing rec", "err", err)
			return false
		}
		time.Sleep(3 * time.Millisecond)
	}
	if err != nil {
		slog.Error("error after 3 retries", "err", err)
		return false
	}
	h.cacheSet(name, ip, ttl)
	return true
}

func (h *Hook) addAddressListRecord(name, ip string, ttl uint) error {
	_, err := h.runClient(
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
	res, err := h.runClient(
		"/ip/firewall/address-list/print",
		fmt.Sprintf("?address=%s", ip),
		fmt.Sprintf("?list=%s", name),
		"?dynamic=yes",
		"=.proplist=.id",
	)
	if err != nil {
		return fmt.Errorf("failed getting address-list: %w", err)
	}
	if len(res.Re) < 1 {
		return errRosAddressNotFound
	}
	_, err = h.runClient(
		"/ip/firewall/address-list/set",
		fmt.Sprintf("=.id=%s", res.Re[0].Map[".id"]),
		fmt.Sprintf("=timeout=%d", ttl),
	)
	if err != nil {
		return fmt.Errorf("failed setting address-list: %w", err)
	}
	slog.Debug("address-list record refreshed", "name", name, "ip", ip, "ttl", ttl)
	return nil
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

func (h *Hook) cachePurge() {
	h.cacheLock.RLock()
	defer h.cacheLock.RUnlock()
	now := time.Now()
	for k, v := range h.cache {
		if v.Before(now) {
			delete(h.cache, k)
		}
	}
}
