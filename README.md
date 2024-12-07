# godnsproxy

[WIP] Simple DNS-proxy to forward A-records to firewall rulesets synchronous

## Usage

```shell
Usage of godnsproxy:
  -f string
        comma-seperated forwarders
  -gttl uint
        grace ttl
  -l string
        log level (debug/info/warn/error) (default "info")
  -m string
        forwarding mode (direct/tproxy) (default "direct")
  -p uint
        listen port (default 53)
  -rosaddr string
        routeros api address
  -rospass string
        routeros password
  -rosuser string
        routeros username
```
