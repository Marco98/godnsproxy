package routeros

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Marco98/godnsproxy/pkg/dnsmatch"
	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

var errRosAddressNotFound = errors.New("no existing address-list record found")

type Hook struct {
	address        string
	username       string
	password       string
	graceTTL       uint
	propagateDelay uint
	restClient     *rest
	matchFqdns     []string
}

func NewRouterOsHook(
	address string,
	username string,
	password string,
	graceTTL uint,
	propagateDelay uint,
	insecure bool,
) *Hook {
	return &Hook{
		address:        address,
		username:       username,
		password:       password,
		graceTTL:       graceTTL,
		propagateDelay: propagateDelay,
		restClient: &rest{
			username: username,
			password: password,
			url:      strings.TrimSuffix(address, "/"),
			client: &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					Proxy: http.ProxyFromEnvironment,
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: insecure, // nolint:gosec
					},
				},
			},
		},
	}
}

func (h *Hook) Hook(resp *dns.Msg) {
	hadEffect := false
	for _, v := range dnsmatch.MatchDNS(resp.Answer, h.matchFqdns) {
		if h.addAddressList(v.Fqdn, v.IPAddress.String(), uint(v.TTL)+h.graceTTL) {
			hadEffect = true
		}
	}
	if hadEffect {
		time.Sleep(time.Duration(h.propagateDelay) * time.Millisecond) //nolint:gosec
	}
}

func (h *Hook) Daemon() {
	for {
		h.updateMatchFqdns()
		time.Sleep(5 * time.Second)
	}
}

func (h *Hook) updateMatchFqdns() {
	rfqdns, err := h.restClient.getMatchFQDNs(context.Background())
	if err != nil {
		slog.Error("error fetching rules", "err", err)
		return
	}
	fqdns := make([]string, 0)
	for _, v := range rfqdns {
		isWC := strings.HasPrefix(v, "*.")
		v, err = idna.Lookup.ToASCII(strings.TrimPrefix(v, "*."))
		if err != nil {
			slog.Debug("could not parse matchFqdn", "fqdn", v, "err", err)
			continue
		}
		if isWC {
			v = fmt.Sprintf("*.%s", v)
		}
		fqdns = append(fqdns, v)
	}
	slog.Debug("fetched matchFqdns from firewall", "resp", len(rfqdns), "count", len(fqdns), "list", fqdns)
	h.matchFqdns = fqdns
}

func (h *Hook) addAddressList(name, ip string, ttl uint) bool {
	log := slog.With("fqdn", name, "ip", ip, "ttl", ttl)
	var err error
	for range 3 {
		err = h.addAddressListRecord(name, ip, ttl)
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "already have such entry") {
			log.Error("error adding rec", "err", err)
			return false
		}
		err = h.refreshAddressList(name, ip, ttl)
		if err == nil {
			break
		}
		if !errors.Is(err, errRosAddressNotFound) {
			log.Error("error refreshing rec", "err", err)
			return false
		}
		time.Sleep(3 * time.Millisecond)
	}
	if err != nil {
		log.Error("error after 3 retries", "err", err)
		return false
	}
	return true
}

func (h *Hook) addAddressListRecord(name, ip string, ttl uint) error {
	if err := h.restClient.addAddressListRecord(context.Background(), name, ip, ttl); err != nil {
		return err
	}
	slog.Info("address-list added", "name", name, "ip", ip, "ttl", ttl)
	return nil
}

func (h *Hook) refreshAddressList(name, ip string, ttl uint) error {
	id, cttl, err := h.restClient.getAddressListRecord(context.Background(), ip, name)
	if err != nil {
		return fmt.Errorf("failed getting address-list: %w", err)
	}
	if len(id) == 0 {
		return errRosAddressNotFound
	}
	if cttl > ttl {
		return nil
	}
	if err := h.restClient.setAddressListRecord(context.Background(), id, ttl); err != nil {
		return fmt.Errorf("failed setting address-list: %w", err)
	}
	slog.Debug("address-list record refreshed", "name", name, "ip", ip, "ttl", ttl)
	return nil
}
