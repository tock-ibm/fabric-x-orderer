/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package types

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chunkedDigestReference is a straightforward single-threaded implementation of the two-level
// chunked digest, used to validate the parallel ChunkedDigest. Level 1 reuses the existing Digest
// on each consecutive group of chunkDigestGroupSize requests; level 2 hashes the concatenation of
// the group digests once.
func chunkedDigestReference(br BatchedRequests, k int) []byte {
	if len(br) == 0 {
		return sha256.New().Sum(nil)
	}

	n := len(br)
	numGroups := (n + k - 1) / k
	combined := make([]byte, 0, numGroups*sha256.Size)
	for g := 0; g < numGroups; g++ {
		lo := g * k
		hi := min(lo+k, n)
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
			assert.Equal(t, chunkedDigestReference(br, chunkDigestGroupSize), d, "n=%d parallel must equal reference", n)
		}
	})

	t.Run("K-parameterized core equals reference for various K", func(t *testing.T) {
		for _, n := range []int{1, 200, 1000, 10000} {
			br := makeRandomRequests(n, 37)
			for _, k := range []int{1, 16, 64, 128, 256, 1024, 20000} {
				assert.Equal(t, chunkedDigestReference(br, k), chunkedDigestK(br, k),
					"n=%d k=%d parallel must equal reference", n, k)
			}
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

// Benchmark_ChunkedK sweeps the group size K for the two-level chunked digest across batch sizes
// from 1000 to 10000 requests (at a fixed request size), to find the K that minimizes elapsed time
// for large batches. For each batch size, compare the ns/op across the "K=" variants: the fastest
// K balances parallelism (more, smaller groups -> more goroutines, up to the core count) against
// overhead (more groups -> more SHA-256 finalizations and a larger second-level hash input).
func Benchmark_ChunkedK(b *testing.B) {
	const reqSize = 300
	ks := []int{16, 32, 64, 128, 256, 512, 1024, 2048}
	for n := 1000; n <= 10000; n += 1000 {
		br := makeRandomRequests(n, reqSize)
		for _, k := range ks {
			b.Run(fmt.Sprintf("reqs=%05d/K=%04d", n, k), func(b *testing.B) {
				b.ReportAllocs()
				var d []byte
				for i := 0; i < b.N; i++ {
					d = chunkedDigestK(br, k)
				}
				require.Len(b, d, 32)
			})
		}
	}
}
