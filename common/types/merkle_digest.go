/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package types

import (
	"crypto/sha256"
	"runtime"
	"sync"
)

// Domain-separation prefixes for the Merkle tree, following RFC 6962 (Certificate Transparency).
// Distinct prefixes for leaves and internal nodes make the tree resistant to second pre-image
// attacks: an attacker cannot present an internal node as a leaf (or vice versa), because the
// hashed byte streams live in disjoint domains.
const (
	merkleLeafPrefix     byte = 0x00
	merkleInternalPrefix byte = 0x01
)

// Shared, read-only single-byte prefix slices, so the hot loops write them without allocating a
// fresh 1-byte slice per hash. hash.Hash.Write never mutates its argument.
var (
	leafPrefix     = []byte{merkleLeafPrefix}
	internalPrefix = []byte{merkleInternalPrefix}
)

// parallelThreshold is the minimum number of nodes in a level below which the level is computed
// on the calling goroutine. Spawning workers for a handful of hashes costs more than it saves.
const parallelThreshold = 512

// MerkleRootDigest computes a Merkle-tree root over the requests, an alternative to Digest that
// parallelizes across CPUs. Each request is a leaf; the dominant cost is hashing the request
// payloads, and that layer is fanned out over runtime.NumCPU() goroutines.
//
// Like Digest, the result is a single 32-byte SHA-256 value, but the two are NOT equal: this is a
// tree hash, not the sequential length-prefixed chain that Digest computes.
//
// The tree is resistant to second pre-image attacks via RFC 6962 domain separation:
//
//	leaf(r)          = SHA256( 0x00 || r )
//	internal(l, r)   = SHA256( 0x01 || l || r )
//
// A level with an odd number of nodes promotes its trailing node unchanged to the next level (it
// is never duplicated, which would reintroduce malleability). An empty or nil batch hashes to
// SHA256(nil).
func (br *BatchedRequests) MerkleRootDigest() []byte {
	if br == nil || len(*br) == 0 {
		return sha256.New().Sum(nil)
	}

	level := computeLeaves(*br)
	for len(level) > 1 {
		level = reduceLevel(level)
	}
	return level[0]
}

// computeLeaves hashes every request into its leaf digest, in parallel over contiguous ranges.
// All leaf hashes share a single backing array so the level costs one allocation, not one per node.
func computeLeaves(reqs BatchedRequests) [][]byte {
	n := len(reqs)
	backing := make([]byte, n*sha256.Size)
	leaves := make([][]byte, n)
	forEachRange(n, func(start, end int) {
		h := sha256.New() // one hasher per worker, reused across its range via Reset
		for i := start; i < end; i++ {
			h.Reset()
			h.Write(leafPrefix)
			h.Write(reqs[i])
			dst := backing[i*sha256.Size : i*sha256.Size : (i+1)*sha256.Size]
			leaves[i] = h.Sum(dst) // appends the 32-byte digest into backing, no allocation
		}
	})
	return leaves
}

// reduceLevel folds one tree level into the next: adjacent pairs become internal nodes, and a
// trailing odd node is promoted unchanged. Pair hashing is parallelized over contiguous ranges.
func reduceLevel(level [][]byte) [][]byte {
	nextLen := (len(level) + 1) / 2
	backing := make([]byte, nextLen*sha256.Size)
	next := make([][]byte, nextLen)

	pairs := len(level) / 2
	forEachRange(pairs, func(start, end int) {
		h := sha256.New() // one hasher per worker, reused across its range via Reset
		for i := start; i < end; i++ {
			h.Reset()
			h.Write(internalPrefix)
			h.Write(level[2*i])
			h.Write(level[2*i+1])
			dst := backing[i*sha256.Size : i*sha256.Size : (i+1)*sha256.Size]
			next[i] = h.Sum(dst) // appends the 32-byte digest into backing, no allocation
		}
	})

	if len(level)%2 == 1 {
		next[nextLen-1] = level[len(level)-1]
	}
	return next
}

// forEachRange invokes work over contiguous, disjoint index ranges covering [0, n), using up to
// runtime.NumCPU() goroutines. For small n (or a single CPU) it runs inline on the caller.
func forEachRange(n int, work func(start, end int)) {
	forEachRangeThreshold(n, parallelThreshold, work)
}

// forEachRangeThreshold is forEachRange with an explicit minimum n at which it fans out to
// goroutines; below threshold (or on a single CPU) it runs inline on the caller. Use a small
// threshold when each unit of work is heavy, a large one when each unit is tiny.
func forEachRangeThreshold(n, threshold int, work func(start, end int)) {
	if n == 0 {
		return
	}

	workers := runtime.NumCPU()
	if n < threshold || workers <= 1 {
		work(0, n)
		return
	}
	workers = min(workers, n)

	chunk := (n + workers - 1) / workers
	var wg sync.WaitGroup
	for start := 0; start < n; start += chunk {
		end := min(start+chunk, n)
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			work(start, end)
		}(start, end)
	}
	wg.Wait()
}
