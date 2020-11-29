package app

import (
	"html/template"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sync"

	"github.com/imgk/shadow/common"
)

type Conn struct {
	io.Closer
	Network    string
	LocalAddr  net.Addr
	RemoteAddr net.Addr
}

type Handler struct {
	common.Handler

	mu    sync.RWMutex
	conns map[uint32]*Conn
}

func NewHandler(h common.Handler) *Handler {
	hd := &Handler{
		Handler: h,
		conns:   make(map[uint32]*Conn),
	}
	http.Handle("/admin/conns", hd)
	return hd
}

func (h *Handler) Handle(conn net.Conn, addr net.Addr) (err error) {
	key := rand.Uint32()

	h.mu.Lock()
	h.conns[key] = &Conn{Closer: conn, Network: "TCP", LocalAddr: conn.RemoteAddr(), RemoteAddr: addr}
	h.mu.Unlock()

	err = h.Handler.Handle(conn, addr)

	h.mu.Lock()
	delete(h.conns, key)
	h.mu.Unlock()

	return
}

func (h *Handler) HandlePacket(conn common.PacketConn) (err error) {
	key := rand.Uint32()

	h.mu.Lock()
	h.conns[key] = &Conn{Closer: conn, Network: "UDP", LocalAddr: conn.RemoteAddr(), RemoteAddr: conn.LocalAddr()}
	h.mu.Unlock()

	err = h.Handler.HandlePacket(conn)

	h.mu.Lock()
	delete(h.conns, key)
	h.mu.Unlock()

	return
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	type Item struct {
		Protocol    string
		Source      string
		Destination string
	}

	type Conns struct {
		Items []Item
	}

	h.mu.RLock()
	conns := Conns{ Items: make([]Item, 0, len(h.conns)) }
	for _, c := range h.conns {
		conns.Items = append(conns.Items, Item{
			Protocol:    c.Network,
			Source:      c.LocalAddr.String(),
			Destination: c.RemoteAddr.String(),
		})
	}
	h.mu.RUnlock()

	connsTemplate.Execute(w, conns)
}

var connsTemplate = template.Must(template.New("").Parse(`
<!DOCTYPE html>
<html>
<head>
<style>
table {
  font-family: arial, sans-serif;
  border-collapse: collapse;
  width: 100%;
}

td, th {
  border: 1px solid #dddddd;
  text-align: left;
  padding: 8px;
}

tr:nth-child(even) {
  background-color: #dddddd;
}
</style>
</head>
<body>

<h2>Active Connections</h2>

<table>
  <tr>
    <th>Protocol</th>
    <th>Source Address</th>
    <th>Destination Address</th>
  </tr>
  {{ range .Items }}
  <tr>
    <td>{{ .Protocol }}</td>
    <td>{{ .Source }}</td>
    <td>{{ .Destination }}</td>
  </tr>
  {{ end }}
</table>

</body>
</html>
`))
