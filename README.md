# Shadow

A shadowsocks, trojan, socks5 and http proxy client for Windows, Linux and macOS.

## How to build

```
# close this repo
git clone https://github.com/imgk/shadow.git

# move to this repo dir
cd shadow

# import one or more protocols
cat <<EOF > main_protocol.go
package main

import _ "github.com/imgk/shadow/proto/shadowsocks"

EOF

# linux darwin windows,wintun
go get -v -ldflags="-s -w" -trimpath

# windows,windivert
go get -v -ldflags="-s -w" -trimpath -tags=shadow_divert
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
iptables -t nat -I POSTROUTING -o $TunName -j ACCEPT
```

### MacOS

1. Set system dns server to 8.8.8.8

```
sudo go/bin/shadow -c /etc/shadow.json -v
```

## Config

Please read [configuration.md](https://github.com/imgk/shadow/blob/master/configuration.md)
