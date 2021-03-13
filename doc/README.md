# Shadow Documentation

## Configuration

Please read [configuration.md](https://github.com/imgk/shadow/blob/main/doc/configuration.md).

## How it works

Please read [howitworks.md](https://github.com/imgk/shadow/blob/main/doc/howitworks.md).

## Example Usage of Shadow

1. Use shadow as DoH client for Windows.

Please use WinDivert.

```json
{
    "server": {
        "protocol": "ss",
        "url": "ss://CHACHA20-IETF-POLY1305:password@127.0.0.1:8388"
    },
    "name_server": "https://1.1.1.1:443/dns-query",
    "windivert_filter_string": "outbound and udp and udp.DstPort == 53",
    "domain_rules": {
        "proxy": [
        ],
        "direct": [
            "**.*"
        ],
        "blocked": [
        ]
    }
}
```

If you are willing to use WinTun, remember to modify Windows route table if shadow does not work as expected. More info please refer [#22](https://github.com/imgk/shadow/issues/22).
```json
{
    "server": {
        "protocol": "ss",
        "url": "ss://CHACHA20-IETF-POLY1305:password@127.0.0.1:8388"
    },
    "name_server": "https://1.1.1.1:443/dns-query",
    "domain_rules": {
        "proxy": [],
        "direct": ["**.*"],
        "blocked": []
    }
}
```

2. Use shadow as transparent proxy on Windows.

```json
```

3. Use shadow as transparent proxy on Linux/OpenWrt/macOS.

