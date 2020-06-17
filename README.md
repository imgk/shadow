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
    // trojan://password@server:port/websocket-path?shadowsocks=chipername
    // trojan://password:mux@server:port/websocket-path?shadowsocks=chipername

    // supported cipher name: CHACHA20-IETF-POLY1305, AES-256-GCM, DUMMY
    "Server": "ss://chacha20-ietf-poly1305:password@127.0.0.1:8388",


    // DNS Server
    // udp://8.8.8.8
    // tcp://8.8.8.8
    // tls://1.1.1.1
    // https://1.1.1.1/dns-query
    // DON'T USE DNS URL with domain name, like https://rubyfish.cn/dns-query
    "NameServer": "https://1.1.1.1/dns-query",


    // Support plugin running in standlone mode
    "Plugin": "obfs-local.exe",
    "PluginOpts": "-s server_ip -p 443 -l 8388 --obfs tls --obfs-host www.example.com",


    // filter string passed to WinDivert
    // https://www.reqrypt.org/windivert-doc.html#filter_language

    // type of server address is ipv4
    // outbound and (ip ? ip.DstAddr != serverip and ip.DstAddr != dnsserverip : true)
    // example: outbound and (ip ? ip.DstAddr != 1.2.3.4 and ip.DstAddr != 1.1.1.1 : true)

    // type of server address is ipv6
    // outbound and (ip ? true : ipv6.DstAddr != serverip and ipv6.DstAddr != dnsserverip)
    // example: outbound and (ip ? true : ipv6.DstAddr != 2001:AEDE:5678::1234 and ipv6.DstAddr != 2001:4860:4860::8888)
    "FilterString": "outbound and (ip ? ip.DstAddr != 1.2.3.4 and ip.DstAddr != 1.1.1.1 : true)",


    // if true, IPs in this list will be proxied
    // if false, IPs in this list will be bypassed
    "IPRules": {
        "Mode": true,
        "IPCIDR": [
            "44.44.0.0/16",
            "91.108.8.0"
        ]
    },


    // if true, programs in this list will be proxied
    // if false, programs in this list will be bypassed
    "AppRules": {
        "Mode": true,
        "Programs":[
            "git.exe"
        ]
    },


    // Fake IP mode
    // domains in proxy list will be given a fake ip: 44.44.X.Y
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