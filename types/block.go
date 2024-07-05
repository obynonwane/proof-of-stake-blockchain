package types

import (
	"crypto/sha256"

	"github.com/obynonwane/blocker/proto"
	pb "google.golang.org/protobuf/proto"
)

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
