package crypto

import (
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
}
