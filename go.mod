module github.com/imgk/shadow

go 1.16

require (
	github.com/gorilla/websocket v1.4.2
	github.com/imgk/divert-go v0.0.0-20201220002345-9b9714564be9
	github.com/lucas-clemente/quic-go v0.19.3
	github.com/miekg/dns v1.1.39
	github.com/oschwald/maxminddb-golang v1.8.0
	github.com/xtaci/smux v1.5.15
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
	golang.org/x/net v0.0.0-20210222171744-9060382bd457
	golang.org/x/sys v0.0.0-20210223095934-7937bea0104d
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba
	golang.zx2c4.com/wireguard v0.0.20200321-0.20201111175144-60b3766b89b9
	golang.zx2c4.com/wireguard/windows v0.3.5
	gvisor.dev/gvisor v0.0.0-20210223000735-2b55523a949a
)

replace golang.zx2c4.com/wireguard => golang.zx2c4.com/wireguard v0.0.0-20210217211927-8bf4204d2ea3
