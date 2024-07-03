package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log"
)

// create some constants
const (
	privKeyLen = 64
	pubKeyLen  = 32
	seedLen    = 32
)

// create a struct of private key
type PrivateKey struct {
	key ed25519.PrivateKey
}

// Bytes returns the private key
func (p *PrivateKey) Bytes() []byte {
	return p.key
}

func GeneratePrivateKey() *PrivateKey {
	//make a slice of byte of seedlen
	seed := make([]byte, seedLen)

	//generate a cryptographically safe random bytes of length seed
	_, err := io.ReadFull(rand.Reader, seed)
	if err != nil {
		log.Panic(err)
	}

	// return the generated private key
	return &PrivateKey{
		key: ed25519.NewKeyFromSeed(seed),
	}
}

// Sign is used to sign message in this case transactions
func (p *PrivateKey) Sign(msg []byte) []byte {
	return ed25519.Sign(p.key, msg)
}

// Public is a function that returns the public key - generated from private key
func (p *PublicKey) Public() *PublicKey {
	//make a slice of length 32 bytes
	b := make([]byte, 32)
	//copy into b the last 32 byte that represents the public key
	copy(b, p.key[32:])

	return &PublicKey{
		key: b,
	}
}

// delcare a truct of public key
type PublicKey struct {
	key ed25519.PublicKey
}
