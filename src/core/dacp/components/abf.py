'''
Benchmark-oriented anonymous Bloom filter component for DACP.

PrototypeABF preserves the current XOR/check-string behavior. It is not a
proved production ABF/GBF construction; it is meant for protocol and algorithm
benchmark plumbing.
'''

import hashlib
import os


class ABFAdapter:
    def build(self, items, params=None):
        raise NotImplementedError

    def query(self, abf, token_id, params=None):
        raise NotImplementedError


class PrototypeABF(ABFAdapter):
    def __init__(self, m=4096, k=3, beta=32):
        self.m = max(64, int(m))
        self.k = max(2, int(k))
        self.beta = max(16, int(beta))

    def build(self, items, params=None):
        params = params or {}
        row_count = int(params.get('row_count', 0))
        if row_count <= 0:
            for rows in items.values():
                if rows:
                    row_count = max(row_count, max(rows) + 1)
        m = int(params.get('m', self.m))
        k = int(params.get('k', self.k))
        beta = int(params.get('beta', self.beta))
        payload_len = row_count + beta

        for _ in range(32):
            seed = os.urandom(16)
            try:
                return self._build_with_seed(items, row_count, seed, payload_len, m, k, beta)
            except RuntimeError:
                continue
        raise RuntimeError('could not build ABF without slot exhaustion')

    def query(self, abf, token_id, params=None):
        seed = bytes.fromhex(abf['seed_ABF'])
        positions = self._positions(seed, token_id, abf['m'], abf['k'])
        recovered = bytes(abf['payload_len'])
        for pos in positions:
            recovered = self._xor_bytes(recovered, abf['slots'][pos])

        bitmap = recovered[:abf['ell']]
        check = recovered[abf['ell']:abf['ell'] + abf['beta']]
        expected = self._check(token_id, abf['beta'])
        if check != expected:
            return []
        return [row_index for row_index, bit in enumerate(bitmap) if bit == 1]

    def digest(self, abf):
        digest = hashlib.sha256()
        digest.update(b'dacp::DigestBF::')
        for slot in abf['slots']:
            digest.update(slot)
        digest.update(abf['seed_ABF'].encode('utf-8'))
        digest.update(str(abf['m']).encode('utf-8'))
        digest.update(str(abf['k']).encode('utf-8'))
        digest.update(str(abf['ell']).encode('utf-8'))
        digest.update(str(abf['beta']).encode('utf-8'))
        return digest.hexdigest()

    def _build_with_seed(self, items, row_count, seed, payload_len, m, k, beta):
        slots = [None] * m
        for token_id, row_indices in items.items():
            positions = self._positions(seed, token_id, m, k)
            free_positions = [pos for pos in positions if slots[pos] is None]
            if not free_positions:
                raise RuntimeError('ABF seed exhausted')
            reserved = free_positions[-1]
            payload = self._payload(row_indices, row_count, token_id, beta)
            acc = bytes(payload_len)
            for pos in positions:
                if pos == reserved:
                    continue
                if slots[pos] is None:
                    slots[pos] = os.urandom(payload_len)
                acc = self._xor_bytes(acc, slots[pos])
            slots[reserved] = self._xor_bytes(acc, payload)

        for index, value in enumerate(slots):
            if value is None:
                slots[index] = os.urandom(payload_len)

        return {
            'slots': slots,
            'seed_ABF': seed.hex(),
            'm': m,
            'k': k,
            'ell': row_count,
            'beta': beta,
            'payload_len': payload_len,
            'prototype': True,
        }

    def _payload(self, row_indices, row_count, token_id, beta):
        bitmap = bytearray(row_count)
        for row_index in row_indices:
            bitmap[row_index] = 1
        return bytes(bitmap) + self._check(token_id, beta)

    def _check(self, token_id, beta):
        return hashlib.sha256(('dacp::H_chk_id::' + token_id).encode('utf-8')).digest()[:beta]

    def _positions(self, seed, token_id, m, k):
        positions = []
        counter = 0
        while len(positions) < k:
            digest = hashlib.sha256(
                b'dacp::H_seed::' + seed + token_id.encode('utf-8') +
                b'::' + str(counter).encode('utf-8')
            ).digest()
            pos = int.from_bytes(digest, byteorder='big') % m
            counter += 1
            if pos not in positions:
                positions.append(pos)
        return positions

    def _xor_bytes(self, left, right):
        return bytes(a ^ b for a, b in zip(left, right))
