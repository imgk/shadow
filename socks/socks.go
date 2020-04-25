package socks

import (
	"errors"
	"io"
	"net"
	"strconv"

	"github.com/imgk/shadowsocks-windivert/utils"
)

const (
	Connect   = 1
	Associate = 3
)

const (
	AuthNone     = 0
	AuthUserPass = 2
)

type Error byte

func (e Error) Error() string {
	switch byte(e) {
	case 0:
		return "succeeded"
	case 1:
		return "general socks server failure"
	case 2:
		return "connection not allowed by ruleset"
	case 3:
		return "Network unreachable"
	case 4:
		return "Host unreachable"
	case 5:
		return "Connection refused"
	case 6:
		return "TTL expired"
	case 7:
		return "Command not supported"
	case 8:
		return "Address type not supported"
	case 9:
		return "to X’FF’ unassigned"
	default:
		return "SOCKS error: " + strconv.Itoa(int(e))
	}
}

const (
	ErrGeneralFailure       = Error(1)
	ErrConnectionNotAllowed = Error(2)
	ErrNetworkUnreachable   = Error(3)
	ErrHostUnreachable      = Error(4)
	ErrConnectionRefused    = Error(5)
	ErrTTLExpired           = Error(6)
	ErrCommandNotSupported  = Error(7)
	ErrAddressNotSupported  = Error(8)
)

func Handshake(conn net.Conn, clientHello []byte, auth *Auth) (utils.Addr, error) {
	if auth == nil {
		return HandshakeWithoutAuth(conn, clientHello)
	}

	b := make([]byte, utils.MaxAddrLen)
	
	b[0], b[1], b[2], b[3] = 5, 2, AuthNone, AuthUserPass
	if _, err := conn.Write(b[:4]); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(conn, b[:2]); err != nil {
		return nil, err
	}
	switch b[1] {
	case AuthNone:
	case AuthUserPass:
		if err := auth.Authenticate(conn); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("not a supported method")
	}

	if _, err := conn.Write(clientHello); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(conn, b[:3]); err != nil {
		return nil, err
	}
	if b[1] != 0 {
		return nil, Error(b[1])
	}

	return utils.ReadAddr(conn)
}

func HandshakeWithoutAuth(conn net.Conn, clientHello []byte) (utils.Addr, error) {
	b := make([]byte, utils.MaxAddrLen)

	b[0], b[1], b[2] = 5, 1, AuthNone
	if _, err := conn.Write(b[:3]); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(conn, b[:2]); err != nil {
		return nil, err
	}
	switch b[1] {
	case AuthNone:
	default:
		return nil, errors.New("not a supported method")
	}

	if _, err := conn.Write(clientHello); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(conn, b[:3]); err != nil {
		return nil, err
	}
	if b[1] != 0 {
		return nil, Error(b[1])
	}

	return utils.ReadAddr(conn)
}

type Auth struct {
	Username string
	Password string
}

func (a *Auth) Authenticate(conn net.Conn) error {
	b := make([]byte, 1+1+255+1+255)

	b[0] = 1
	b[1] = byte(len(a.Username))
	n := 2
	n += copy(b[n:], []byte(a.Username))
	b[n] = byte(len(a.Password))
	n++
	n += copy(b[n:], []byte(a.Password))

	if _, err := conn.Write(b[:n]); err != nil {
		return err
	}

	if _, err := io.ReadFull(conn, b[:2]); err != nil {
		return err
	}

	if b[1] == 0 {
		return nil
	}

	return errors.New("authenticate error")
}
