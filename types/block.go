package types

import (
	"crypto/sha256"

	"github.com/obynonwane/blocker/crypto"
	"github.com/obynonwane/blocker/proto"
	pb "google.golang.org/protobuf/proto"
)

/*
* SignBlock: signs the hash of the block commited by the validator
* using the account private key (pk)
 */
func SignBlock(pk *crypto.PrivateKey, b *proto.Block) *crypto.Signature {
	return pk.Sign(HashBlock(b))
}

/*
* HashBlock: returns SHA254 of the Header
* Hashing block does not hash the block itself,
* we going to hash the header
 */
func HashBlock(block *proto.Block) []byte {
	b, err := pb.Marshal(block)
	if err != nil {
		panic(err)
	}

	hash := sha256.Sum256(b)

	return hash[:]
}
