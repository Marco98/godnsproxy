package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net"
	"strings"
)

type cli struct {
	logLevel         string
	mode             string
	port             uint
	graceTTL         uint
	propagateDelay   uint
	forwarders       string
	routerosAddress  string
	routerosUsername string
	routerosPassword string
	insecure         bool
}

type config struct {
	mode             string
	port             uint16
	graceTTL         uint
	propagateDelay   uint
	forwarders       []string
	routerosAddress  string
	routerosUsername string
	routerosPassword string
	insecure         bool
}

var logLevels = map[string]slog.Level{
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
}

func getCliParams() cli {
	cli := cli{}
	flag.StringVar(&cli.logLevel, "l", "info", "log level (debug/info/warn/error)")
	flag.StringVar(&cli.mode, "m", "direct", "forwarding mode (direct/tproxy)")
	flag.UintVar(&cli.port, "p", 53, "listen port")
	flag.UintVar(&cli.graceTTL, "gttl", 1, "grace ttl (default 1)")
	flag.UintVar(&cli.propagateDelay, "pdel", 100, "propagate delay (ms)")
	flag.StringVar(&cli.forwarders, "f", "", "comma-separated forwarders")
	flag.StringVar(&cli.routerosAddress, "rosaddr", "", "routeros restapi address")
	flag.StringVar(&cli.routerosUsername, "rosuser", "", "routeros username")
	flag.StringVar(&cli.routerosPassword, "rospass", "", "routeros password")
	flag.BoolVar(&cli.insecure, "insecure", false, "skip tls verification")
	flag.Parse()
	return cli
}

func parseConfig() (config, error) {
	cli, cfg := getCliParams(), config{}
	slogLevel, ok := logLevels[strings.ToLower(cli.logLevel)]
	if !ok {
		return cfg, fmt.Errorf("invalid loglevel: %s", cli.logLevel)
	}
	slog.SetLogLoggerLevel(slogLevel)
	cfg, ok = cli.makeConfig()
	if !ok {
		return cfg, errors.New("arguments are invalid")
	}
	return cfg, nil
}

func (cli cli) makeConfig() (config, bool) {
	valid, cfg := true, config{}
	cfg.mode = cli.mode
	if cli.mode == "direct" {
		cfg.mode = cli.mode
	} else {
		valid = false
		slog.Error("only direct-mode is currently supported", "arg", "m", "val", cli.mode)
	}
	if cli.port > 0 || cli.port < math.MaxUint16 {
		cfg.port = uint16(cli.port) //nolint:gosec
	} else {
		valid = false
		slog.Error("listen port out of bounds (1-65535)", "arg", "p", "val", cli.port)
	}
	if len(cli.routerosUsername) > 0 {
		cfg.routerosUsername = cli.routerosUsername
	} else {
		valid = false
		slog.Error("routeros username is not set", "arg", "rosuser", "val", cli.routerosUsername)
	}
	if len(cli.routerosPassword) > 0 {
		cfg.routerosPassword = cli.routerosPassword
	} else {
		valid = false
		slog.Error("routeros password is not set", "arg", "rospass", "val", "redacted")
	}
	cfg.forwarders = strings.Split(cli.forwarders, ",")
	for _, v := range cfg.forwarders {
		if net.ParseIP(v) == nil {
			valid = false
			slog.Error("invalid ip address as forwarder", "arg", "f", "val", cli.forwarders)
		}
	}
	cfg.routerosAddress = cli.routerosAddress
	cfg.graceTTL = cli.graceTTL
	cfg.propagateDelay = cli.propagateDelay
	cfg.insecure = cli.insecure
	return cfg, valid
}
