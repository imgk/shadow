package socks

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/imgk/shadow/common"
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
	switch e {
	case ErrSuccess:
		return "succeeded"
	case ErrGeneralFailure:
		return "general socks server failure"
	case ErrConnectionNotAllowed:
		return "connection not allowed by ruleset"
	case ErrNetworkUnreachable:
		return "Network unreachable"
	case ErrHostUnreachable:
		return "Host unreachable"
	case ErrConnectionRefused:
		return "Connection refused"
	case ErrTTLExpired:
		return "TTL expired"
	case ErrCommandNotSupported:
		return "Command not supported"
	case ErrAddressNotSupported:
		return "Address type not supported"
	default:
		return "socks error: " + strconv.Itoa(int(e))
	}
}

const (
	ErrSuccess              = Error(0)
	ErrGeneralFailure       = Error(1)
	ErrConnectionNotAllowed = Error(2)
	ErrNetworkUnreachable   = Error(3)
	ErrHostUnreachable      = Error(4)
	ErrConnectionRefused    = Error(5)
	ErrTTLExpired           = Error(6)
	ErrCommandNotSupported  = Error(7)
	ErrAddressNotSupported  = Error(8)
)

func Handshake(conn net.Conn, tgt net.Addr, cmd byte, auth *Auth) (common.Addr, error) {
	b := make([]byte, 3+common.MaxAddrLen)

	if auth == nil {
		b[0], b[1], b[2] = 5, 1, AuthNone
		if _, err := conn.Write(b[:3]); err != nil {
			return nil, err
		}	
	} else {
		b[0], b[1], b[2], b[3] = 5, 2, AuthNone, AuthUserPass
		if _, err := conn.Write(b[:4]); err != nil {
			return nil, err
		}	
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

	b[0], b[1], b[2] = 5, cmd, 0
	if addr, ok := tgt.(common.Addr); ok {
		copy(b[3:], addr)
		if _, err := conn.Write(b[:3+len(addr)]); err != nil {
			return nil, err
		}
	} else {
		addr, err := common.ResolveAddrBuffer(tgt, b[3:])
		if err != nil {
			return nil, fmt.Errorf("resolve addr error: %w", err)
		}

		if _, err := conn.Write(b[:3+len(addr)]); err != nil {
			return nil, err
		}
	}

	if _, err := io.ReadFull(conn, b[:3]); err != nil {
		return nil, err
	}
	if b[1] != 0 {
		return nil, Error(b[1])
	}

	return common.ReadAddrBuffer(conn, b)
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
