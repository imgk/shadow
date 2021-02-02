module github.com/imgk/shadow/protocol

go 1.16

require (
	github.com/gorilla/websocket v1.4.2
	github.com/imgk/shadow v0.0.0-20210202113752-1b8fb97b9018
	github.com/lucas-clemente/quic-go v0.19.3
	github.com/xtaci/smux v1.5.15
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	golang.org/x/net v0.0.0-20210119194325-5f4716e94777
	golang.org/x/time v0.0.0-20201208040808-7e3f01d25324
)

replace github.com/imgk/shadow => ../
