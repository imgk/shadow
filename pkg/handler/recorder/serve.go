package recorder

import (
	"html/template"
	"net"
	"net/http"
	"sort"
)

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
