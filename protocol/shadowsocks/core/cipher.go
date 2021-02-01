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

// Cipher is ...
type Cipher struct {
	// KeySize is ...
	KeySize int
	// SaltSize is ...
	SaltSize int
	// NewAEAD is ...
	NewAEAD func([]byte) (cipher.AEAD, error)
}

// NewCipher is ...
func NewCipher(method, password string) (*Cipher, error) {
	const KeySize = 32
	const SaltSize = 32

	key := func(password string, keyLen int) []byte {
		buff := []byte{}
		prev := []byte{}
		hash := md5.New()
		for len(buff) < keyLen {
			hash.Write(prev)
			hash.Write([]byte(password))
			buff = hash.Sum(buff)
			prev = buff[len(buff)-hash.Size():]
			hash.Reset()
		}
		return buff[:keyLen]
	}(password, KeySize)

	switch strings.ToUpper(method) {
	case "AES-256-GCM", "AEAD_AES_256_GCM":
		cipher := &Cipher{
			KeySize:  KeySize,
			SaltSize: SaltSize,
			NewAEAD: func(salt []byte) (cipher.AEAD, error) {
				subkey := make([]byte, KeySize)
				hkdfSHA1(key, salt, subkey)
				block, err := aes.NewCipher(subkey)
				if err != nil {
					return nil, err
				}
				return cipher.NewGCM(block)
			},
		}
		return cipher, nil
	case "CHACHA20-IETF-POLY1305", "AEAD_CHACHA20_POLY1305":
		cipher := &Cipher{
			KeySize:  KeySize,
			SaltSize: SaltSize,
			NewAEAD: func(salt []byte) (cipher.AEAD, error) {
				subkey := make([]byte, KeySize)
				hkdfSHA1(key, salt, subkey)
				return chacha20poly1305.New(subkey)
			},
		}
		return cipher, nil
	case "DUMMY":
		return &Cipher{NewAEAD: nil}, nil
	default:
		return nil, errors.New("not support method")
	}
}

func hkdfSHA1(secret, salt, outkey []byte) {
	r := hkdf.New(sha1.New, secret, salt, []byte("ss-subkey"))
	if _, err := io.ReadFull(r, outkey); err != nil {
		panic(err)
	}
}
