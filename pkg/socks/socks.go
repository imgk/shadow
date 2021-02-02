package socks

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"golang.org/x/net/proxy"
)

const (
	// CmdConnect is ..
	CmdConnect = 1
	// CmdAssociate is ...
	CmdAssociate = 3
	// AuthNone is ...
	AuthNone = 0
	// AuthUserPass is ...
	AuthUserPass = 2
)

// Error is ...
type Error byte

// Error is ...
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
	// ErrSuccess is ...
	ErrSuccess = Error(0)
	// ErrGeneralFailure is ...
	ErrGeneralFailure = Error(1)
	// ErrConnectionNotAllowed is ...
	ErrConnectionNotAllowed = Error(2)
	// ErrNetworkUnreachable is ...
	ErrNetworkUnreachable = Error(3)
	// ErrHostUnreachable is ...
	ErrHostUnreachable = Error(4)
	// ErrConnectionRefused is ...
	ErrConnectionRefused = Error(5)
	// ErrTTLExpired is ...
	ErrTTLExpired = Error(6)
	// ErrCommandNotSupported is ...
	ErrCommandNotSupported = Error(7)
	// ErrAddressNotSupported is ...
	ErrAddressNotSupported = Error(8)
)

// Handshake (client side) is to talk to server
func Handshake(conn net.Conn, tgt net.Addr, cmd byte, auth *proxy.Auth) (*Addr, error) {
	b := make([]byte, 3+MaxAddrLen)

	// send supported methods
	if auth == nil {
		bb := append(b[:0], 5, 1, AuthNone)
		if _, err := conn.Write(bb); err != nil {
			return nil, err
		}
	} else {
		bb := append(b[:0], 5, 2, AuthNone, AuthUserPass)
		if _, err := conn.Write(bb); err != nil {
			return nil, err
		}
	}

	// read response
	if _, err := io.ReadFull(conn, b[:2]); err != nil {
		return nil, err
	}
	switch b[1] {
	case AuthNone:
	case AuthUserPass:
		// send user name and password to server
		if err := func(conn net.Conn, auth *proxy.Auth) error {
			b := append(make([]byte, 0, 1+1+255+1+255), 1)
			b = append(b, byte(len(auth.User)))
			b = append(b, []byte(auth.User)...)
			b = append(b, byte(len(auth.Password)))
			b = append(b, []byte(auth.Password)...)

			if _, err := conn.Write(b); err != nil {
				return err
			}

			if _, err := io.ReadFull(conn, b[:2]); err != nil {
				return err
			}
			if b[1] == 0 {
				return nil
			}

			return errors.New("authenticate error")
		}(conn, auth); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("not a supported method")
	}

	// send target address
	b[0], b[1], b[2] = 5, cmd, 0
	if addr, ok := tgt.(*Addr); ok {
		copy(b[3:], addr.Addr)
		if _, err := conn.Write(b[:3+len(addr.Addr)]); err != nil {
			return nil, err
		}
	} else {
		addr, err := ResolveAddrBuffer(tgt, b[3:])
		if err != nil {
			return nil, fmt.Errorf("resolve addr error: %w", err)
		}

		if _, err := conn.Write(b[:3+len(addr.Addr)]); err != nil {
			return nil, err
		}
	}

	// read response
	if _, err := io.ReadFull(conn, b[:3]); err != nil {
		return nil, err
	}
	if b[1] != 0 {
		return nil, Error(b[1])
	}

	return ReadAddrBuffer(conn, b)
}
