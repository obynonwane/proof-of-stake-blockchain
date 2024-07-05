package crypto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateKey(t *testing.T) {
	//generate private key
	privKey := GeneratePrivateKey()

	//make assertion that the private key generated is of correct lenght
	assert.Equal(t, len(privKey.key), privKeyLen)

	pubKey := privKey.Public()
	assert.Equal(t, len(pubKey.Byte()), pubKeyLen)
}

func TestPrivateKeyFromString(t *testing.T) {

	var (
		seed       = "447e9e133c4c17155ecb739388e06b80d8444d70d5ff43541f6cdf43ab13cf61"
		addressStr = "3505405aa008c  9b5bac40f5f88254299e61cf13f"
		privKey    = NewPrivateKeyFromString(seed)
	)
	assert.Equal(t, privKeyLen, len(privKey.Bytes()))
	address := privKey.Public().Address()
	assert.Equal(t, addressStr, address.String())

	// io.ReadFull(rand.Reader, seed)
	// fmt.Println(hex.EncodeToString(seed))
}

func TestPrivateKeySign(t *testing.T) {
	//create private key
	privKey := GeneratePrivateKey()
	//get public key
	pubKey := privKey.Public()
	//create message
	msg := []byte("foo bar baz")
	//sign the message/transaction
	sig := privKey.Sign(msg)
	//create asertion that return true if verification is succesful
	assert.True(t, sig.Verify(pubKey, msg))
	//test with invalid message/transaction
	assert.False(t, sig.Verify(pubKey, []byte("foo")))
	//test with invalid public key
	invalidfPrivkey := GeneratePrivateKey()
	invalidPubKey := invalidfPrivkey.Public()
	assert.False(t, sig.Verify(invalidPubKey, msg))
}

func TestPublicKeyToAddress(t *testing.T) {
	//create private key
	privKey := GeneratePrivateKey()
	//get public key
	pubKey := privKey.Public()
	//create address
	address := pubKey.Address()
	assert.Equal(t, addressLen, len(address.Bytes()))

	fmt.Println(address)

}
