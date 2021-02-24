# Shadow

A shadowsocks, trojan, socks5 and http proxy client for Windows, Linux and macOS.

## How to build

Build with Go 1.16. Replace `$(proto)` with proxies you want to use. Currently shadow supports `socks`, `shadowsocks`, `trojan`, `http`.

```
git clone https://github.com/imgk/shadow.git
cd shadow

# linux darwin windows,wintun
go build -v -ldflags="-s -w" -trimpath -tags="$(proto)" github.com/imgk/shadow

# windows,windivert
go build -v -ldflags="-s -w" -trimpath -tags="divert $(proto)" github.com/imgk/shadow
```

## How to use it

```
->  ~ go/bin/shadow -h
Usage of go/bin/shadow:
  -c string
        config file (default "config.json")
  -t duration
        timeout (default 1m0s)
  -v    enable verbose mode
```

### Windows

For WinTun, download [wintun](https://www.wintun.net) and put `wintun.dll` in `C:\Windows\System32`.
For WinDivert, download [WinDivert](https://www.reqrypt.org/windivert.html) 2.2 and put `WinDivert.dll` and `WinDivert64.sys` in `C:\Windows\System32`.

Run shadow.exe with administrator privilege.
```
go/bin/shadow.exe -c C:/Users/example/shadow/config.json -v
```

### Linux and Openwrt Router

1. Set system dns server to 8.8.8.8

```
sudo go/bin/shadow -c /etc/shadow.json -v
```

```
# configure firewall if necessary
iptables -I FORWARD -o $TunName -j ACCEPT
iptables -t nat -I POSTROUTING -o $TunName -j MASQUERADE
```

### MacOS

1. Set system dns server to 8.8.8.8

```
sudo go/bin/shadow -c /etc/shadow.json -v
```

## Config

Please read [configuration.md](https://github.com/imgk/shadow/blob/main/configuration.md)
