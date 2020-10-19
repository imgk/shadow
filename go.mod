module github.com/imgk/shadow

go 1.15

require (
	github.com/eycorsican/go-tun2socks v1.16.11
	github.com/golang/protobuf v1.4.3 // indirect
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/websocket v1.4.2
	github.com/lucas-clemente/quic-go v0.18.1
	github.com/marten-seemann/qtls-go1-15 v0.1.1 // indirect
	github.com/miekg/dns v1.1.34
	github.com/oschwald/maxminddb-golang v1.7.0
	github.com/xtaci/smux v1.5.14
	go.uber.org/multierr v1.6.0
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
	golang.org/x/net v0.0.0-20201016165138-7b1cca2348c0
	golang.org/x/sys v0.0.0-20201018230417-eeed37f84f13
	golang.zx2c4.com/wireguard v0.0.20200321-0.20200607075020-f28a6d244b51
	golang.zx2c4.com/wireguard/windows v0.1.1
	google.golang.org/protobuf v1.25.0 // indirect
)

replace golang.org/x/sys => golang.org/x/sys v0.0.0-20200602225109-6fdc65e7d980
