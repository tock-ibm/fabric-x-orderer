/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package types

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hashLeaf(req []byte) []byte {
	h := sha256.New()
	h.Write([]byte{merkleLeafPrefix})
	h.Write(req)
	return h.Sum(nil)
}

func hashInternal(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{merkleInternalPrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// merkleRootReference is a straightforward single-threaded Merkle root, identical in semantics to
// MerkleRootDigest. It exists to validate the parallel implementation.
func merkleRootReference(br BatchedRequests) []byte {
	if len(br) == 0 {
		return sha256.New().Sum(nil)
	}

	level := make([][]byte, len(br))
	for i, r := range br {
		level[i] = hashLeaf(r)
	}

	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i+1 < len(level); i += 2 {
			next = append(next, hashInternal(level[i], level[i+1]))
		}
		if len(level)%2 == 1 {
			next = append(next, level[len(level)-1])
		}
		level = next
	}
	return level[0]
}

func makeRandomRequests(count, size int) BatchedRequests {
	reqs := make(BatchedRequests, count)
	for i := 0; i < count; i++ {
		r := make([]byte, size)
		_, _ = rand.Read(r)
		reqs[i] = r
	}
	return reqs
}

func TestMerkleRootDigest(t *testing.T) {
	t.Run("nil and empty produce the same 32-byte root", func(t *testing.T) {
		var brNil *BatchedRequests
		assert.Len(t, brNil.MerkleRootDigest(), 32)

		var brEmpty BatchedRequests
		assert.Len(t, brEmpty.MerkleRootDigest(), 32)
		assert.Equal(t, brNil.MerkleRootDigest(), brEmpty.MerkleRootDigest())
	})

	t.Run("single request equals its leaf hash", func(t *testing.T) {
		br := BatchedRequests{[]byte("hello")}
		leaf := sha256.Sum256(append([]byte{merkleLeafPrefix}, []byte("hello")...))
		assert.Equal(t, leaf[:], br.MerkleRootDigest())
	})

	t.Run("various sizes: parallel equals reference and is 32 bytes", func(t *testing.T) {
		for _, n := range []int{0, 1, 2, 3, 4, 5, 7, 8, 9, 100, 1000, 10000} {
			br := makeRandomRequests(n, 37)
			root := br.MerkleRootDigest()
			assert.Len(t, root, 32)
			assert.Equal(t, merkleRootReference(br), root, "n=%d parallel must equal reference", n)
		}
	})

	t.Run("deterministic across repeated calls", func(t *testing.T) {
		br := makeRandomRequests(10000, 300)
		first := br.MerkleRootDigest()
		for i := 0; i < 5; i++ {
			assert.Equal(t, first, br.MerkleRootDigest())
		}
	})

	t.Run("distinct batches yield distinct roots", func(t *testing.T) {
		br1 := BatchedRequests{[]byte{1}, []byte{2}, []byte{3}}
		br2 := BatchedRequests{[]byte{1}, []byte{2}, []byte{4}}
		assert.NotEqual(t, br1.MerkleRootDigest(), br2.MerkleRootDigest())
	})

	t.Run("order sensitive", func(t *testing.T) {
		br1 := BatchedRequests{[]byte{1}, []byte{2}}
		br2 := BatchedRequests{[]byte{2}, []byte{1}}
		assert.NotEqual(t, br1.MerkleRootDigest(), br2.MerkleRootDigest())
	})

	t.Run("leaf/internal domain separation resists second pre-image", func(t *testing.T) {
		// Two leaves whose combined root must not collide with a single leaf whose
		// content is the concatenation of the two internal children. Domain-separation
		// prefixes (0x00 for leaves, 0x01 for internal nodes) guarantee this.
		a := []byte("aaaa")
		b := []byte("bbbb")
		twoLeaves := BatchedRequests{a, b}

		leafA := sha256.Sum256(append([]byte{merkleLeafPrefix}, a...))
		leafB := sha256.Sum256(append([]byte{merkleLeafPrefix}, b...))
		forged := BatchedRequests{append(leafA[:], leafB[:]...)}

		assert.NotEqual(t, twoLeaves.MerkleRootDigest(), forged.MerkleRootDigest())
	})
}

func Benchmark_DigestVsMerkleRoot(b *testing.B) {
	br := makeRandomRequests(10000, 300)

	b.Run("LinearDigest", func(b *testing.B) {
		b.ReportAllocs()
		var d []byte
		for i := 0; i < b.N; i++ {
			d = br.Digest()
		}
		require.Len(b, d, 32)
	})

	b.Run("MerkleRoot", func(b *testing.B) {
		b.ReportAllocs()
		var d []byte
		for i := 0; i < b.N; i++ {
			d = br.MerkleRootDigest()
		}
		require.Len(b, d, 32)
	})
}
