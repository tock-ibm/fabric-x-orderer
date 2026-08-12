/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package types

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

// chunkedDigestReference is a straightforward single-threaded implementation of the two-level
// chunked digest, used to validate the parallel ChunkedDigest. Level 1 reuses the existing Digest
// on each consecutive group of chunkDigestGroupSize requests; level 2 hashes the concatenation of
// the group digests once.
func chunkedDigestReference(br BatchedRequests) []byte {
	if len(br) == 0 {
		return sha256.New().Sum(nil)
	}

	n := len(br)
	numGroups := (n + chunkDigestGroupSize - 1) / chunkDigestGroupSize
	combined := make([]byte, 0, numGroups*sha256.Size)
	for g := 0; g < numGroups; g++ {
		lo := g * chunkDigestGroupSize
		hi := min(lo+chunkDigestGroupSize, n)
		group := br[lo:hi]
		combined = append(combined, group.Digest()...)
	}
	root := sha256.Sum256(combined)
	return root[:]
}

func TestChunkedDigest(t *testing.T) {
	t.Run("nil and empty produce the same 32-byte digest", func(t *testing.T) {
		var brNil *BatchedRequests
		assert.Len(t, brNil.ChunkedDigest(), 32)

		var brEmpty BatchedRequests
		assert.Len(t, brEmpty.ChunkedDigest(), 32)
		assert.Equal(t, brNil.ChunkedDigest(), brEmpty.ChunkedDigest())
	})

	t.Run("various sizes: parallel equals reference and is 32 bytes", func(t *testing.T) {
		// Include sizes around and across the K=128 group boundary and multi-group counts.
		for _, n := range []int{1, 2, 127, 128, 129, 255, 256, 257, 1000, 10000} {
			br := makeRandomRequests(n, 37)
			d := br.ChunkedDigest()
			assert.Len(t, d, 32)
			assert.Equal(t, chunkedDigestReference(br), d, "n=%d parallel must equal reference", n)
		}
	})

	t.Run("deterministic across repeated calls", func(t *testing.T) {
		br := makeRandomRequests(10000, 300)
		first := br.ChunkedDigest()
		for i := 0; i < 5; i++ {
			assert.Equal(t, first, br.ChunkedDigest())
		}
	})

	t.Run("distinct batches yield distinct digests", func(t *testing.T) {
		br1 := makeRandomRequests(1000, 37)
		br2 := make(BatchedRequests, len(br1))
		copy(br2, br1)
		br2[500] = append([]byte{0xff}, br2[500]...) // perturb one request in the second group
		assert.NotEqual(t, br1.ChunkedDigest(), br2.ChunkedDigest())
	})

	t.Run("differs from Digest and MerkleRootDigest", func(t *testing.T) {
		br := makeRandomRequests(1000, 37)
		assert.NotEqual(t, br.Digest(), br.ChunkedDigest())
		assert.NotEqual(t, br.MerkleRootDigest(), br.ChunkedDigest())
	})
}
