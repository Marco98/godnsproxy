package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net"
	"strconv"
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
}

var logLevels = map[string]slog.Level{
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
}

func parseConfig() (config, error) {
	cli, cfg := cli{}, config{}
	flag.StringVar(&cli.logLevel, "l", "info", "log level (debug/info/warn/error)")
	flag.StringVar(&cli.mode, "m", "direct", "forwarding mode (direct/tproxy)")
	flag.UintVar(&cli.port, "p", 53, "listen port")
	flag.UintVar(&cli.graceTTL, "gttl", 0, "grace ttl")
	flag.UintVar(&cli.propagateDelay, "pdel", 15, "propagate delay (ms)")
	flag.StringVar(&cli.forwarders, "f", "", "comma-seperated forwarders")
	flag.StringVar(&cli.routerosAddress, "rosaddr", "", "routeros api address")
	flag.StringVar(&cli.routerosUsername, "rosuser", "", "routeros username")
	flag.StringVar(&cli.routerosPassword, "rospass", "", "routeros password")
	flag.Parse()
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
	rosAddrSplit := strings.Split(cli.routerosAddress, ":")
	if len(rosAddrSplit) == 2 {
		if net.ParseIP(rosAddrSplit[0]) != nil {
			rosAddrPort, err := strconv.ParseUint(rosAddrSplit[1], 10, 16)
			if err == nil {
				cfg.routerosAddress = fmt.Sprintf("%s:%d", rosAddrSplit[0], rosAddrPort)
			} else {
				valid = false
				slog.Error("routeros address api port is not valid", "arg", "rosaddr", "val", cli.routerosAddress)
			}
		} else {
			valid = false
			slog.Error("routeros address ip address is not valid", "arg", "rosaddr", "val", cli.routerosAddress)
		}
	} else {
		valid = false
		slog.Error("routeros address + api port must be set", "arg", "rosaddr", "val", cli.routerosAddress)
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
	cfg.graceTTL = cli.graceTTL
	cfg.propagateDelay = cli.propagateDelay
	return cfg, valid
}
