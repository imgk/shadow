package app

import (
	"html/template"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/imgk/shadow/common"
)

// netConn is methods shared by net.Conn and common.PacketConn
type netConn interface {
	io.Closer
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// Reader implements net.Conn.Read and common.PacketConn.ReadTo
// and record the number of bytes
type Reader struct {
	num     uint64
	conn    net.Conn
	pktConn common.PacketConn
}

func (r *Reader) Read(b []byte) (n int, err error) {
	n, err = r.conn.Read(b)
	atomic.AddUint64(&r.num, uint64(n))
	return
}

func (r *Reader) Close() error {
	if closer, ok := r.conn.(common.CloseReader); ok {
		return closer.CloseRead()
	}
	r.conn.SetReadDeadline(time.Now())
	return r.conn.Close()
}

func (r *Reader) ReadTo(b []byte) (n int, addr net.Addr, err error) {
	n, addr, err = r.pktConn.ReadTo(b)
	atomic.AddUint64(&r.num, uint64(n))
	return
}

func (r *Reader) ByteNum() uint64 {
	return atomic.LoadUint64(&r.num)
}

// Writer implements net.Conn.Write and common.PacketConn.WriteFrom
// and record the number of bytes
type Writer struct {
	num     uint64
	conn    net.Conn
	pktConn common.PacketConn
}

func (w *Writer) Write(b []byte) (n int, err error) {
	n, err = w.conn.Write(b)
	atomic.AddUint64(&w.num, uint64(n))
	return
}

func (w *Writer) Close() error {
	if closer, ok := w.conn.(common.CloseWriter); ok {
		return closer.CloseWrite()
	}
	w.conn.SetWriteDeadline(time.Now())
	return w.conn.Close()
}

func (w *Writer) WriteFrom(b []byte, addr net.Addr) (n int, err error) {
	n, err = w.pktConn.WriteFrom(b, addr)
	atomic.AddUint64(&w.num, uint64(n))
	return
}

func (w *Writer) ByteNum() uint64 {
	return atomic.LoadUint64(&w.num)
}

// Conn implements net.Conn and common.PacketConn
// and record the number of bytes it reads and writes
type Conn struct {
	netConn
	Reader        Reader
	Writer        Writer
	preTime       time.Time
	preRead       uint64
	preWrite      uint64
	Network       string
	LocalAddress  net.Addr
	RemoteAddress net.Addr
}

func NewConnFromConn(conn net.Conn, addr net.Addr) (c *Conn) {
	c = &Conn{
		netConn: conn,
		Reader: Reader{
			num:     0,
			conn:    conn,
			pktConn: nil,
		},
		Writer: Writer{
			num:     0,
			conn:    conn,
			pktConn: nil,
		},
		preTime:       time.Now(),
		preRead:       0,
		preWrite:      0,
		Network:       "TCP",
		LocalAddress:  conn.RemoteAddr(),
		RemoteAddress: addr,
	}
	return
}

func NewConnFromPacketConn(conn common.PacketConn) (c *Conn) {
	c = &Conn{
		netConn: conn,
		Reader: Reader{
			num:     0,
			conn:    nil,
			pktConn: conn,
		},
		Writer: Writer{
			num:     0,
			conn:    nil,
			pktConn: conn,
		},
		preTime:       time.Now(),
		preRead:       0,
		preWrite:      0,
		Network:       "UDP",
		LocalAddress:  conn.RemoteAddr(),
		RemoteAddress: conn.LocalAddr(),
	}
	return
}

func (c *Conn) Read(b []byte) (int, error) {
	return c.Reader.Read(b)
}

func (c *Conn) CloseRead() error {
	return c.Reader.Close()
}

func (c *Conn) Write(b []byte) (int, error) {
	return c.Writer.Write(b)
}

func (c *Conn) CloseWrite() error {
	return c.Writer.Close()
}

func (c *Conn) ReadTo(b []byte) (int, net.Addr, error) {
	return c.Reader.ReadTo(b)
}

func (c *Conn) WriteFrom(b []byte, addr net.Addr) (int, error) {
	return c.Writer.WriteFrom(b, addr)
}

func (c *Conn) Nums() (rb uint64, rs uint64, wb uint64, ws uint64) {
	rb = c.Reader.ByteNum()
	wb = c.Writer.ByteNum()

	prev := c.preTime
	c.preTime = time.Now()
	duration := c.preTime.Sub(prev).Seconds()

	rs = uint64(float64(rb-c.preRead) / duration)
	ws = uint64(float64(wb-c.preWrite) / duration)

	c.preRead = rb
	c.preWrite = wb

	return
}

// Handler implements common.Handler which can record all active
// connections
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
	return hd
}

func (h *Handler) Handle(conn net.Conn, addr net.Addr) (err error) {
	key := rand.Uint32()
	conn = NewConnFromConn(conn, addr)

	h.mu.Lock()
	h.conns[key] = conn.(*Conn)
	h.mu.Unlock()

	err = h.Handler.Handle(conn, addr)

	h.mu.Lock()
	delete(h.conns, key)
	h.mu.Unlock()

	return
}

func (h *Handler) HandlePacket(conn common.PacketConn) (err error) {
	key := rand.Uint32()
	conn = NewConnFromPacketConn(conn)

	h.mu.Lock()
	h.conns[key] = conn.(*Conn)
	h.mu.Unlock()

	err = h.Handler.HandlePacket(conn)

	h.mu.Lock()
	delete(h.conns, key)
	h.mu.Unlock()

	return
}

func (h *Handler) Close() (err error) {
	h.mu.Lock()
	for _, c := range h.conns {
		c.Close()
	}
	h.mu.Unlock()
	err = h.Handler.Close()
	return
}

type ByteNum uint64

func (n ByteNum) String() (str string) {
	const mask = (^uint64(0)) >> (64 - 10)

	str = ""
	for _, unit := range []string{" B", " K, ", " M, ", " G, ", " T, "} {
		if n > 0 {
			str = strconv.FormatUint(uint64(n)&mask, 10) + unit + str
			n = n >> 10
			continue
		}
		if str == "" {
			str = "0 B"
		}
	}

	return
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	type ConnItem struct {
		ConnID        uint32   `json:"id"`
		Protocol      string   `json:"protocol"`
		Source        net.Addr `json:"source_address"`
		Destination   net.Addr `json:"destination_address`
		Upload        ByteNum  `json:"upload_bytes"`
		UploadSpeed   ByteNum  `json:"upload_speed"`
		Download      ByteNum  `json:"download_bytes"`
		DownloadSpeed ByteNum  `json:"download_speed"`
	}

	h.mu.RLock()
	conns := make([]*ConnItem, 0, len(h.conns))
	for k, c := range h.conns {
		rb, rs, wb, ws := c.Nums()
		conns = append(conns, &ConnItem{
			ConnID:        k,
			Protocol:      c.Network,
			Source:        c.LocalAddress,
			Destination:   c.RemoteAddress,
			Upload:        ByteNum(rb),
			UploadSpeed:   ByteNum(rs),
			Download:      ByteNum(wb),
			DownloadSpeed: ByteNum(ws),
		})
	}
	h.mu.RUnlock()

	sort.Slice(conns, func(i, j int) bool {
		return conns[i].ConnID < conns[j].ConnID
	})

	type ConnsInfo struct {
		ConnNum   int
		ConnSlice []*ConnItem
	}

	connsTemplate.Execute(w, ConnsInfo{ConnNum: len(conns), ConnSlice: conns})
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

<h2>Active Connections - {{ .ConnNum }}</h2>

<table>
  <tr>
    <th>ID</th>
    <th>Protocol</th>
    <th>Source Address</th>
    <th>Destination Address</th>
    <th>Upload Bytes</th>
    <th>Upload Speed</th>
    <th>Download Bytes</th>
    <th>Download Speed</th>
  </tr>
  {{ range .ConnSlice }}
  <tr>
    <td>{{ .ConnID }}</td>
    <td>{{ .Protocol }}</td>
    <td>{{ .Source }}</td>
    <td>{{ .Destination }}</td>
    <td>{{ .Upload }}</td>
    <td>{{ .UploadSpeed }}</td>
    <td>{{ .Download }}</td>
    <td>{{ .DownloadSpeed }}</td>
  </tr>
  {{ end }}
</table>

</body>
</html>
`))
