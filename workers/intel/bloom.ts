// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Tiny bloom filter for threat-intel membership checks.
 *
 * Purpose: cheap "is this URL/domain on a known-bad list" test without
 * shipping a multi-MB list to every hot-path request. A positive match
 * still triggers a secondary exact-blob set-membership check before we act
 * on it — bloom false-positives must not cause blocking.
 *
 * Sizing: m = ceil(-n * ln(p) / (ln(2))^2), k = ceil((m/n) * ln(2))
 * For n = 100k entries, p = 0.01 → m ≈ 958k bits (≈120KB), k ≈ 7.
 */

const FNV_OFFSET_32 = 2166136261;
const FNV_PRIME_32 = 16777619;

/**
 * FNV-1a 32-bit hash. Two independent hashes are derived by varying a seed;
 * k hashes are built via the standard double-hashing construction
 * h_i(x) = (h1(x) + i * h2(x)) mod m.
 */
function fnv1a(value: string, seed: number): number {
	let hash = (FNV_OFFSET_32 ^ seed) >>> 0;
	for (let i = 0; i < value.length; i++) {
		hash ^= value.charCodeAt(i);
		hash = Math.imul(hash, FNV_PRIME_32) >>> 0;
	}
	return hash >>> 0;
}

export interface BloomFilter {
	bits: Uint8Array;
	m: number;
	k: number;
}

export function createBloom(n: number, p = 0.01): BloomFilter {
	const m = Math.max(64, Math.ceil((-n * Math.log(p)) / Math.LN2 ** 2));
	const mBytes = Math.ceil(m / 8);
	const k = Math.max(1, Math.round((m / Math.max(n, 1)) * Math.LN2));
	return { bits: new Uint8Array(mBytes), m, k };
}

function positions(value: string, m: number, k: number): number[] {
	const h1 = fnv1a(value, 0x9e3779b9);
	const h2 = fnv1a(value, 0x85ebca6b) || 1;
	const out: number[] = new Array(k);
	for (let i = 0; i < k; i++) {
		out[i] = (h1 + i * h2) % m;
	}
	return out;
}

export function addToBloom(filter: BloomFilter, value: string) {
	for (const pos of positions(value, filter.m, filter.k)) {
		filter.bits[pos >>> 3] |= 1 << (pos & 7);
	}
}

export function checkBloom(filter: BloomFilter, value: string): boolean {
	for (const pos of positions(value, filter.m, filter.k)) {
		if ((filter.bits[pos >>> 3] & (1 << (pos & 7))) === 0) return false;
	}
	return true;
}

/**
 * Serialise to a compact binary with a 12-byte header:
 *   bytes 0-3  "BLM1" magic
 *   bytes 4-7  m (uint32 little-endian)
 *   bytes 8-11 k (uint32 little-endian)
 *   bytes 12+  bits
 */
export function serializeBloom(filter: BloomFilter): Uint8Array {
	const out = new Uint8Array(12 + filter.bits.length);
	out[0] = 0x42; out[1] = 0x4c; out[2] = 0x4d; out[3] = 0x31; // "BLM1"
	const dv = new DataView(out.buffer);
	dv.setUint32(4, filter.m, true);
	dv.setUint32(8, filter.k, true);
	out.set(filter.bits, 12);
	return out;
}

export function deserializeBloom(buf: ArrayBuffer | Uint8Array): BloomFilter | null {
	const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
	if (bytes.length < 12) return null;
	if (bytes[0] !== 0x42 || bytes[1] !== 0x4c || bytes[2] !== 0x4d || bytes[3] !== 0x31) return null;
	const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	const m = dv.getUint32(4, true);
	const k = dv.getUint32(8, true);
	const bits = bytes.slice(12);
	return { bits, m, k };
}
