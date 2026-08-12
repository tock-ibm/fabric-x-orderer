/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package types

import (
	"crypto/sha256"
	"encoding/binary"
)

// chunkDigestGroupSize (K) is the number of consecutive requests reduced into a single first-level
// group digest by ChunkedDigest.
const chunkDigestGroupSize = 128

// chunkParallelThreshold is the minimum number of groups at which ChunkedDigest fans the first
// level out to goroutines. Each group hashes up to K requests, so a group is heavy work and it is
// worth parallelizing even for a handful of them.
const chunkParallelThreshold = 2

// ChunkedDigest computes a two-level digest over the requests, a third alternative to Digest and
// MerkleRootDigest that keeps Digest's cheap streaming leaf hashing but still parallelizes:
//
//	level 1: split the requests into consecutive groups of K=chunkDigestGroupSize; reduce each
//	         group with the SAME length-prefixed SHA-256 chain as Digest. Groups are hashed in
//	         parallel across runtime.NumCPU() goroutines.
//	level 2: concatenate the M = ceil(N/K) group digests and hash them once, on a single goroutine.
//
// Unlike the Merkle tree it performs only M+1 SHA-256 finalizations (not ~2N), so it does barely
// more work than Digest while still spreading the payload hashing across cores. The result is a
// single 32-byte value and is not equal to Digest or MerkleRootDigest. An empty or nil batch
// hashes to SHA256(nil).
func (br *BatchedRequests) ChunkedDigest() []byte {
	if br == nil || len(*br) == 0 {
		return sha256.New().Sum(nil)
	}

	reqs := *br
	n := len(reqs)
	numGroups := (n + chunkDigestGroupSize - 1) / chunkDigestGroupSize

	// Level 1: one group digest per K requests, written into a shared backing array (disjoint
	// slots, no locking), computed in parallel.
	groupDigests := make([]byte, numGroups*sha256.Size)
	forEachRangeThreshold(numGroups, chunkParallelThreshold, func(start, end int) {
		h := sha256.New()           // one hasher per worker, reused across its groups via Reset
		sizeBuff := make([]byte, 4) // one length buffer per worker
		for g := start; g < end; g++ {
			lo := g * chunkDigestGroupSize
			hi := min(lo+chunkDigestGroupSize, n)
			h.Reset()
			for _, r := range reqs[lo:hi] {
				binary.BigEndian.PutUint32(sizeBuff, uint32(len(r)))
				h.Write(sizeBuff)
				h.Write(r)
			}
			dst := groupDigests[g*sha256.Size : g*sha256.Size : (g+1)*sha256.Size]
			h.Sum(dst)
		}
	})

	// Level 2: combine the group digests into the final digest on a single goroutine.
	root := sha256.Sum256(groupDigests)
	return root[:]
}
