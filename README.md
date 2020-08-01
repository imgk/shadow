# Shadow

A shadowsocks, trojan and socks5 client for Windows, Linux and macOS.

## How to build

```
# linux darwin windows,!wintun
go build -v -ldflags="-s -w" -trimpath

# windows,wintun
go build -v -ldflags="-s -w" -trimpath -tags=wintun
```

## How to use it

```
->  ~ go/bin/shadow -h
Usage of go/bin/shadow:
  -c string
    	config file (default "config.json")
  -v	enable verbose mode
```

### Windows

#### a. WinDivert

Run shadow.exe with administrator privilege.
```
go/bin/shadow.exe -c C:/Users/example/shadow/config.json -v
```

#### b. WinTun

Due to the limitation of WinTun, please run shadow with PSExec(`PSExec -s -i /path/to/shadow.exe -c /path/to/config/json -v`) in [PSTools](https://docs.microsoft.com/zh-cn/sysinternals/downloads/pstools) or with a service wrapper, such as [nssm](https://nssm.cc) and [winsw](https://github.com/winsw/winsw).

### Linux and Openwrt Router

1. Set system dns server to 8.8.8.8

```
sudo go/bin/shadow -c /etc/shadow.json -v
```

```
# configure firewall if necessary
iptables -I FORWARD -o $TunName -j ACCEPT
iptables -t nat -I POSTROUTING -o $TunName -j ACCEPT
```

### MacOS

1. Set system dns server to 8.8.8.8

```
sudo go/bin/shadow -c /etc/shadow.json -v
```

## Config File
```
{
    // Proxy Server

    // Shadowsocks
    // ss://ciphername:password@server:port

    // Socks5
    // socks://username:password@server:port

    // Trojan-GFW
    // trojan://password@server:port

    // Trojan-GO (VERSION > 0.7.0)
    // trojan://password:mux@server:port
    // trojan://password@server:port/websocket-path?aead=chipername
    // trojan://password:mux@server:port/websocket-path?aead=chipername

    // supported cipher name: CHACHA20-IETF-POLY1305, AES-256-GCM, DUMMY
    "Server": [
        "ss://chacha20-ietf-poly1305:password@127.0.0.1:8388",
        "trojan://password:mux@example.com:443/path?aead=ciphername"
    ],


    // DNS Server
    // udp://8.8.8.8
    // tcp://8.8.8.8
    // tls://1.1.1.1
    // https://1.1.1.1/dns-query
    "NameServer": "https://1.1.1.1/dns-query",


    // windivert only
    // filter string passed to WinDivert
    // https://www.reqrypt.org/windivert-doc.html#filter_language

    // type of server address is ipv4
    // outbound and (ip ? ip.DstAddr != serverip and ip.DstAddr != dnsserverip : true)
    // example: outbound and (ip ? ip.DstAddr != 1.2.3.4 and ip.DstAddr != 1.1.1.1 : true)

    // type of server address is ipv6
    // outbound and (ip ? true : ipv6.DstAddr != serverip and ipv6.DstAddr != dnsserverip)
    // example: outbound and (ip ? true : ipv6.DstAddr != 2001:AEDE:5678::1234 and ipv6.DstAddr != 2001:4860:4860::8888)
    "FilterString": "outbound and (ip ? ip.DstAddr != 1.2.3.4 and ip.DstAddr != 1.1.1.1 : true)",


    // tun device only
    "TunName": "utun",
    "TunAddr": [
        "192.168.0.11/24"
    ],


    // IPs in this list will be proxied
    "IPCIDRRules": {
        "Proxy": [
            "198.18.0.0/16",
            "8.8.8.8/32"
        ]
    },


    // windivert only
    // programs in this list will be proxied
    "AppRules": {
        "Proxy":[
            "git.exe"
        ]
    },


    // Fake IP mode
    // shadow will hijack all UDP dns queries
    // except IPs with prefix of 198.18
    // domains in proxy list will be given a fake ip: 198.18.X.Y
    // and packets to these domains will be proxied
    "DomainRules": {
        "Proxy": [
            "**.google.com",
            "**.google.*",
            "**.google.*.*",
            "**.youtube.com",
            "*.twitter.com",
            "www.facebook.com",
            "bing.com",
            "**.amazon.*"
        ],
        "Direct": [
            "**.baidu.*",
            "**.youku.*",
            "**.*"
        ],
        "Blocked": [
            "ad.blocked.com"
        ]
    }
}
```
