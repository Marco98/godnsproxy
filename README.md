# godnsproxy

[WIP] Simple DNS-proxy to forward A-records to firewall rulesets synchronous

## Features / Ideas

- [x] DNS-based firewall rules
  - [x] RouterOS (Mikrotik) - i will only support ROSv7
  - [ ] nftables (Linux)
  - [ ] kubernetes (in the stars...)
- [ ] DNS A-record NAT rules
- [ ] DNS filter lists

## Usage

### Flags

```shell
Usage of godnsproxy:
  -f string
        comma-separated forwarders
  -gttl uint
        grace ttl
  -l string
        log level (debug/info/warn/error) (default "info")
  -m string
        forwarding mode (direct/tproxy) (default "direct")
  -p uint
        listen port (default 53)
  -pdel uint
        propagate delay (ms) (default 100)
  -rosaddr string
        routeros api address
  -rospass string
        routeros password
  -rosuser string
        routeros username
```

### Usage in RouterOS Firewall Rules

Just create a firewall rule with either a FQDN or a Wildcard-FQDN as *dst-address-list*.
Thats it.
The dst-address-list does not need to exist.
The godnsproxy-daemon will detect this fqdn and listens for it.
When a dns request hits the proxy it will populate the address-list.

### Deploy on RouterOS

> Please keep in mind that this is only a example.
> IP-addresses and naming may and should differ from your systems.
> Also note that firewall allow-rules probably are needed for this to work.

```RouterOS
/interface veth
add name=veth-proxy address=172.31.15.2/30 gateway=172.31.15.1
/interface bridge
add name=bridge-ct protocol-mode=none
port add bridge=bridge-ct interface=veth-proxy
/ip address
add address=172.31.15.1/30 interface=bridge-ct network=172.31.15.0
/user
add address=172.31.15.2/32 group=full name=godnsproxy password=securepass
/container
config set registry-url=https://ghcr.io tmpdir=ct_images
add interface=veth-proxy logging=yes start-on-boot=yes comment=godnsproxy \
remote-image=ghcr.io/marco98/godnsproxy:latest \
cmd="-rosaddr 172.31.15.1:8728 -rosuser godnsproxy -rospass securepass -f 1.1.1.1,1.0.0.1 -l warn"
/ip dns
set servers=172.31.15.2
```

### Gotchas / Tuning

**Grace-TTL** (-gttl)

In a clean environment this shouldn't be required.
However when dns caching is done dirty, applications are bad designed or some weird low-ttl-cdn-quirks are happening you can increase the TTL received by upstream dns.
This does not affect the DNS-response the client receives. It only changes the time the dynamic firewall rule stays open.
Per default the Grace-TTL is set to 1sec to account for the propagation delay and the connection buildup from client after receiving the dns-response.

**Propagation-Delay** (-pdel)

Sadly api-calls to RouterOS don't seem to be synchronous. So there is a unpredictable delay between creating a firewall-rule and the rule actually being effective.
For this reason there is a delay between the successful api-call to the router and answering the dns request.
The default is 100ms which seems to be a stable delay when testing.
The delay of course only applies when a api-call to the router is necessary.

**Caching**

This is not a replacement for dns caching. A DNS-Cache can and should be places either before or behind godnsproxy.
In a clean setup the order shouldn't matter. However placing it before cache reduces load, after it needs to trust the cache to respect the TTLs.

## Development

### Deploy on RouterOS

```shell
ROUTER_SSH=admin@192.168.2.10
ROUTER_APIUSER=godnsproxy
ROUTER_APIPASS=securepass
goreleaser --snapshot --clean && \
docker image save -o dist/snapshot-image.tar ghcr.io/marco98/godnsproxy && \
scp "dist/snapshot-image.tar" "${ROUTER_SSH}:godnsproxy.tar" && \
ssh $ROUTER_SSH /container stop \[find comment=godnsproxy\] && \
sleep 3s && \
ssh $ROUTER_SSH /container remove \[find comment=godnsproxy\] && \
ssh $ROUTER_SSH /container add \
interface=veth-proxy logging=yes start-on-boot=yes comment=godnsproxy file=godnsproxy.tar \
cmd=\"-rosaddr 172.31.15.1:8728 -rosuser $ROUTER_APIUSER -rospass $ROUTER_APIPASS -f 1.1.1.1,1.0.0.1 -l warn\" && \
ssh $ROUTER_SSH /container start \[find comment=godnsproxy\] && \
ssh $ROUTER_SSH /file remove godnsproxy.tar
```
