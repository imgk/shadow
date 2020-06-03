# Shadow

A shadowsocks, trojan and socks5 client for Windows, Linux and MacOS.

## How to use it

```
➜  ~ go/bin/shadow -h
Usage of go/bin/shadow:
  -c string
    	config file (default "config.json")
  -v	enable verbose mode
```

### Windows

1. Put config.json and shadow.exe in same directory, then run shadow.exe with administrator privilege.

### Linux and Openwrt Router

1. set system dns server to 8.8.8.8

```
sudo TunName=utun8 TunAddr=192.168.0.11/24 TunRoute="44.44.0.0/16;8.8.8.8/32" go/bin/shadow -c /etc/shadow.json -v
```

```
# configure firewall if necessary
iptables -I FORWARD -o $TunName -j ACCEPT
iptables -t nat -I POSTROUTING -o $TunName -j ACCEPT
```

### MacOS

1. set system dns server to 8.8.8.8

```
sudo TunName=utun8 TunAddr=192.168.0.11/24 TunRoute="44.44.0.0/16;8.8.8.8/32" go/bin/shadow -c /etc/shadow.json -v
```

## Config File

1. Support socks5, shadowsocks, trojan

```
ss://ciphername:password@server:port
socks://username:password@server:port
trojan://password[:mux]@server:port[/websocket-path]
```

Currently shadowsocks only support CHACHA20-IETF-POLY1305, AES-256-GCM and DUMMY for no encryption/decryption.

For websocket for trojan, set double tls off and obfs on. The obfs password is identical with trojan password.

2. Support DNS over HTTPS and DNS over TLS

```
udp://8.8.8.8
tcp://8.8.8.8
tls://1.1.1.1
https://1.1.1.1/dns-query
```

DNS over HTTPS and DNS over TLS DO NOT support domain url.

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
