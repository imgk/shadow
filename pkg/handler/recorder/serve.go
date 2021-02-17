package recorder

import (
	"html/template"
	"log"
	"net"
	"net/http"
	"sort"

	"github.com/imgk/shadow/pkg/embed"
)

var connsTemplate = template.Must(template.ParseFS(embed.Files, "admin.conns.html"))

// ServeHTTP is ...
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	type ConnItem struct {
		ConnID        uint32   `json:"id"`
		Protocol      string   `json:"protocol"`
		Source        net.Addr `json:"source_address"`
		Destination   net.Addr `json:"destination_address"`
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

	if err := connsTemplate.Execute(w, ConnsInfo{ConnNum: len(conns), ConnSlice: conns}); err != nil {
		log.Panic(err)
	}
}
