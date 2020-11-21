package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

func hkdfSHA1(secret, salt, outkey []byte) {
	r := hkdf.New(sha1.New, secret, salt, []byte("ss-subkey"))
	if _, err := io.ReadFull(r, outkey); err != nil {
		panic(err)
	}
}

type Cipher interface {
	KeySize() int
	SaltSize() int
	NewAead([]byte) (cipher.AEAD, error)
}

type aes256gcm struct {
	psk []byte
}

func (aes256gcm) KeySize() int  { return 32 }
func (aes256gcm) SaltSize() int { return 32 }

func (a aes256gcm) NewAead(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, a.KeySize())
	hkdfSHA1(a.psk, salt, subkey)
	block, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

type chacha20ietfpoly1305 struct {
	psk []byte
}

func (chacha20ietfpoly1305) KeySize() int  { return 32 }
func (chacha20ietfpoly1305) SaltSize() int { return 32 }

func (c chacha20ietfpoly1305) NewAead(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, c.KeySize())
	hkdfSHA1(c.psk, salt, subkey)

	return chacha20poly1305.New(subkey)
}

type dummy struct{}

func (dummy) KeySize() int                          { return 0 }
func (dummy) SaltSize() int                         { return 0 }
func (dummy) NewAead(_ []byte) (cipher.AEAD, error) { return nil, nil }

func NewCipher(method, password string) (Cipher, error) {
	switch strings.ToUpper(method) {
	case "AES-256-GCM", "AEAD_AES_256_GCM":
		return aes256gcm{psk: kdf(password, 32)}, nil
	case "CHACHA20-IETF-POLY1305", "AEAD_CHACHA20_POLY1305":
		return chacha20ietfpoly1305{psk: kdf(password, 32)}, nil
	case "DUMMY":
		return dummy{}, nil
	default:
		return nil, errors.New("not support method")
	}
}

func kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}
