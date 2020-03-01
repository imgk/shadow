# Shadowsocks-WinDivert

A shadowsocks Windows client based on WinDviert. 

## How to use it

Build Shadowsocks-WinDivert and Divert driver. Run shadowsocks-windivert.exe as administrator.

shadowsocks-windivert.exe -c rule.json -s ss://AEAD_CHACHA20_POLY1305:password@server:port -u -v
