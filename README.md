# Shadowsocks-WinDivert

A shadowsocks client for Windows, Linux and MacOS.

## How to use it

### Windows

1. Download [WinDivert](https://github.com/basil00/Divert/releases) and put `WinDivert.dll` and `WinDivert64.sys` in `C:\Windows\system32`. Run shadowsocks.exe with administrator privilege.

### Linux and Openwrt Router

1. setup `127.0.0.1#5300` as dnsmasq name server upstream

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
ipset add gfwlist 8.8.4.4
ipset add gfwlist 1.1.1.1
ipset add gfwlist 1.0.0.1

iptables -t mangle -N FWMARK
iptables -t mangle -A PREROUTING -j FWMARK
iptables -t mangle -A OUTPUT -j FWMARK
iptables -t mangle -A FWMARK -m set --match-set gfwlist dst -j MARK --set-mark 1

ip route add default via 192.168.0.1 dev utun table gfwlist
ip rule add FWMARK 1 table gfwlist

#for openwrt router
iptables -I FORWARD -o utun -j ACCEPT
iptables -t nat -I POSTROUTING -o utun -j ACCEPT
```
### MacOS
1. set system dns server to 127.0.0.1

2. configure interface and route table

```
sudo ifconfig [tunname] inet 192.168.0.2 netmask 255.255.255.0 192.168.0.1

sudo route -n add -net 44.44.0.0/16 192.168.0.1
sudo route -n add -net 8.8.8.8 192.168.0.1
sudo route -n add -net 8.8.4.4 192.168.0.1
```
## Config File

1. Support socks5, shadowsocks, trojan

```
socks://username:password@server:port
ss://DUMMY:password@server:port
ss://password@server:port
```

Currently shadowsocks only support CHACHA20-IETF-POLY1305, AES-256-GCM and DUMMY for no encryption/decryption.

2. Support DNS over https and DNS over TLS

```
local:port=https://rubyfish.cn/dns-query
local:port=tls://rubyfish.cn/
```

3. Filter String

Visit [WinDivert document](https://www.reqrypt.org/windivert-doc.html#filter_language) for details.

4. `Mode` about IP rules and program rules

If `true`, items in the lists will be proxied.

## Plugin

Plugin should work in standalone mode.
