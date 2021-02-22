package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"errors"
	"io"
	"log"
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

// Key is ...
type Key []byte

// AES256GCM is ...
// generate AES-256-GCM cipher
func (k Key) AES256GCM(salt []byte) (cipher.AEAD, error) {
	const KeySize = 32

	subkey := make([]byte, KeySize)
	hkdfSHA1([]byte(k), salt, subkey)
	block, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Chacha20Poly1305 is ...
// generate Chacha20-IETF-Poly1305 cipher
func (k Key) Chacha20Poly1305(salt []byte) (cipher.AEAD, error) {
	const KeySize = 32

	subkey := make([]byte, KeySize)
	hkdfSHA1([]byte(k), salt, subkey)
	return chacha20poly1305.New(subkey)
}

// NewCipher is ...
func NewCipher(method, password string) (*Cipher, error) {
	return NewCipherFromKey(method, password, nil)
}

// NewCipherFromKey is ...
func NewCipherFromKey(method, password string, key []byte) (*Cipher, error) {
	const KeySize = 32
	const SaltSize = 32

	if key == nil || len(key) < KeySize {
		key = func(password []byte, keyLen int) []byte {
			buff := []byte{}
			prev := []byte{}
			hash := md5.New()
			for len(buff) < keyLen {
				hash.Write(prev)
				hash.Write(password)
				buff = hash.Sum(buff)
				prev = buff[len(buff)-hash.Size():]
				hash.Reset()
			}
			return buff[:keyLen]
		}([]byte(password), KeySize)
	}
	key = key[:KeySize]

	switch strings.ToUpper(method) {
	case "AES-256-GCM", "AEAD_AES_256_GCM":
		cipher := &Cipher{
			KeySize:  KeySize,
			SaltSize: SaltSize,
			NewAEAD:  Key(key).AES256GCM,
		}
		return cipher, nil
	case "CHACHA20-IETF-POLY1305", "AEAD_CHACHA20_POLY1305":
		cipher := &Cipher{
			KeySize:  KeySize,
			SaltSize: SaltSize,
			NewAEAD:  Key(key).Chacha20Poly1305,
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
		log.Panic(err)
	}
}
