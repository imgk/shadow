# Shadow

A shadowsocks, trojan and socks5 client for Windows, Linux and MacOS.

## How to use it

### Windows

1. Run shadow.exe with administrator privilege.

### Linux and Openwrt Router

1. setup `8.8.8.8#53` as dnsmasq name server upstream

2. add a line in `/etc/iproute2/rt_tables`
```
200 gfwlist
```

3. Setup device and route table.
```
#for Linux
ip address add dev utun 192.168.0.2/24
ip link set up dev utun

ipset -N gfwlist hash:net
ipset add gfwlist 44.44.0.0/16
ipset add gfwlist 8.8.8.8

iptables -t mangle -N fwmark
iptables -t mangle -A PREROUTING -j fwmark
iptables -t mangle -A OUTPUT -j fwmark
iptables -t mangle -A fwmark -m set --match-set gfwlist dst -j MARK --set-mark 1

ip route add default via 192.168.0.1 dev utun table gfwlist
ip rule add fwmark 1 table gfwlist

#for openwrt router
iptables -I FORWARD -o utun -j ACCEPT
iptables -t nat -I POSTROUTING -o utun -j ACCEPT
```
### MacOS
1. set system dns server to 8.8.8.8

2. configure interface and route table

```
sudo ifconfig [tunname] inet 192.168.0.2 netmask 255.255.255.0 192.168.0.1

sudo route -n add -net 44.44.0.0/16 192.168.0.1
sudo route -n add -net 8.8.8.8 192.168.0.1
```
## Config File

1. Support socks5, shadowsocks, trojan

```
ss://ciphername:password@server:port
socks://username:password@server:port
trojan://password@server:port
```

Currently shadowsocks only support CHACHA20-IETF-POLY1305, AES-256-GCM and DUMMY for no encryption/decryption.

2. Support DNS over HTTPS and DNS over TLS

```
udp://8.8.8.8
tcp://8.8.8.8
tls://rubyfish.cn
https://rubyfish.cn/dns-query
```

3. Filter String (Windows only)

```
# type of server address is ipv4
outbound and (ip ? ip.DstAddr != serverip and ip.DstAddr != dnsserverip : true)

# type of server address is ipv6
outbound and (ip ? true : ipv6.DstAddr != serverip and ipv6.DstAddr != dnsserverip)
```

Visit [WinDivert document](https://www.reqrypt.org/windivert-doc.html#filter_language) for details.

4. `Mode` about IP rules and program rules

If `true`, items in the lists will be proxied.

## Plugin

Plugin should work in standalone mode.
