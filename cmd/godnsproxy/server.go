package main

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/Marco98/godnsproxy/pkg/routeros"
	"github.com/miekg/dns"
)

func run() error {
	cfg, err := parseConfig()
	if err != nil {
		return err
	}
	hooks = append(hooks, routeros.NewRouterOsHook(
		cfg.routerosAddress,
		cfg.routerosUsername,
		cfg.routerosPassword,
		cfg.graceTTL,
		cfg.propagateDelay,
		cfg.insecure,
	))
	runHookDaemons()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", handleDNSRequest(cfg))
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: int(cfg.port),
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	err = dns.ActivateAndServe(nil, conn, mux)
	if err != nil {
		return err
	}
	return nil
}

func handleDNSRequest(cfg config) func(w dns.ResponseWriter, r *dns.Msg) {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		var resp *dns.Msg
		var err error
		log := slog.With("client", w.RemoteAddr().String())
		if len(r.Question) > 0 {
			log = log.With("rname", r.Question[0].Name)
			log.Debug("rx dns req")
		}
		for _, v := range cfg.forwarders {
			resp, err = dns.Exchange(r, fmt.Sprintf("%s:%d", v, 53))
			if err == nil {
				break
			}
		}
		if err != nil {
			log.Warn("error forwarding request", "err", err)
			m := new(dns.Msg)
			m.SetReply(r)
			m.SetRcode(r, dns.RcodeServerFailure)
			if err := w.WriteMsg(m); err != nil {
				log.Error("error writing error", "err", err)
			}
			return
		}
		runHooks(resp)
		if len(resp.Answer) > 0 {
			a, ok := resp.Answer[0].(*dns.A)
			if ok {
				log = log.With("tname", a.Hdr.Name, "tip", a.A.String())
				log.Debug("tx dns resp")
			}
		}
		if err := w.WriteMsg(resp); err != nil {
			log.Error("error writing response", "err", err)
		}
	}
}
