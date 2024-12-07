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
	hooks = append(hooks, &routeros.Hook{
		Address:        cfg.routerosAddress,
		Username:       cfg.routerosUsername,
		Password:       cfg.routerosPassword,
		GraceTTL:       cfg.graceTTL,
		PropagateDelay: cfg.propagateDelay,
	})
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
		for _, v := range cfg.forwarders {
			resp, err = dns.Exchange(r, fmt.Sprintf("%s:%d", v, 53))
			if err == nil {
				break
			}
		}
		if err != nil {
			slog.Warn("error forwarding request", "err", err)
			m := new(dns.Msg)
			m.SetReply(r)
			m.SetRcode(r, dns.RcodeServerFailure)
			if err := w.WriteMsg(m); err != nil {
				slog.Error("error writing error", "err", err)
			}
			return
		}
		runHooks(resp)
		if err := w.WriteMsg(resp); err != nil {
			slog.Error("error writing response", "err", err)
		}
	}
}
