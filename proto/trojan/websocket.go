package trojan

import (
	"errors"
	"io"
	"time"

	"github.com/gorilla/websocket"
)

// emptyReader is ...
type emptyReader struct{}

// Read is ...
func (*emptyReader) Read(b []byte) (int, error) {
	return 0, io.EOF
}

// wsConn is ...
type wsConn struct {
	*websocket.Conn
	Reader io.Reader
}

// Read is ..
func (c *wsConn) Read(b []byte) (int, error) {
	n, err := c.Reader.Read(b)
	if n > 0 {
		return n, nil
	}

	_, c.Reader, err = c.Conn.NextReader()
	if err != nil {
		if we := (*websocket.CloseError)(nil); errors.As(err, &we) {
			return 0, io.EOF
		}
		return 0, err
	}

	n, err = c.Reader.Read(b)
	return n, nil
}

// Write is ...
func (c *wsConn) Write(b []byte) (int, error) {
	err := c.Conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		if we := (*websocket.CloseError)(nil); errors.As(err, &we) {
			return 0, io.EOF
		}
		return 0, err
	}
	return len(b), nil
}

// SetDeadline is ...
func (c *wsConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}

// Close is ...
func (c *wsConn) Close() error {
	msg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
	err := c.Conn.WriteControl(websocket.CloseMessage, msg, time.Now().Add(time.Second*5))
	if err != nil {
		c.Conn.Close()
		return err
	}
	return c.Conn.Close()
}
