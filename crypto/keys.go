package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
)

// create some constants
const (
	privKeyLen = 64
	pubKeyLen  = 32
	seedLen    = 32
	addressLen = 20
)

// create a struct of private key
type PrivateKey struct {
	key ed25519.PrivateKey
}

// NewPrivateKeyFromString: convert string into slice of bytes
func NewPrivateKeyFromString(s string) *PrivateKey {
	// this conver strings into slice of bytes
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}

	return NewPrivateKeyFromSeed(b)
}

// NewPrivateKeyFromSeed: generate new private key from supplied seed
func NewPrivateKeyFromSeed(seed []byte) *PrivateKey {
	if len(seed) != seedLen {
		panic("invalid seed length, must be 32")
	}

	return &PrivateKey{
		key: ed25519.NewKeyFromSeed(seed),
	}
}

// Bytes returns the private key
func (p *PrivateKey) Bytes() []byte {
	return p.key
}

// GeneratePrivateKey: generates private key
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
func (p *PrivateKey) Sign(msg []byte) *Signature {
	return &Signature{
		value: ed25519.Sign(p.key, msg),
	}
}

// Public is a function that creates the public key - generated from private key
func (p *PrivateKey) Public() *PublicKey {
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

func (p *PublicKey) Address() Address {
	return Address{
		value: p.key[len(p.key)-addressLen:], //extracts the last 20 bytes
	}
}

// Byte return the public key
func (p *PublicKey) Byte() []byte {
	return p.key
}

type Signature struct {
	value []byte
}

// Bytes returns the signed message or transaction
func (s *Signature) Bytes() []byte {
	return s.value
}

// Verify verifies the  message or transaction (msg or transaction are hashes)
func (s *Signature) Verify(pubKey *PublicKey, msg []byte) bool {
	// pubkey, transactionhash & signature
	return ed25519.Verify(pubKey.key, msg, s.value)
}

type Address struct {
	value []byte
}

func (a Address) Bytes() []byte {
	return a.value
}

// String returns acount address
func (a Address) String() string {
	return hex.EncodeToString(a.value)
}
