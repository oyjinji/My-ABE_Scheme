'''
Prototype certificate authority for DACP.

PrototypeCertificateAuthority is a lightweight benchmark certificate issuer. It
checks required fields, validity windows, optional subject public-key binding,
and an optional CA signature. It is not an X.509 chain, revocation, or CA policy
implementation.
'''

import hashlib
import json
import time


class CertificateAuthority:
    def issue_cert(self, subject, public_key, **kwargs):
        raise NotImplementedError

    def verify_cert(self, cert, **kwargs):
        raise NotImplementedError


class PrototypeCertificateAuthority(CertificateAuthority):
    def __init__(self, issuer='Prototype-CA', signature=None,
                 ca_sk=None, ca_pk=None, default_lifetime=86400.0):
        self.issuer = issuer
        self.signature = signature
        self.default_lifetime = float(default_lifetime)
        self.ca_sk = ca_sk
        self.ca_pk = ca_pk
        if self.signature is not None and (self.ca_sk is None or self.ca_pk is None):
            self.ca_sk, self.ca_pk = self.signature.keygen()

    def issue_cert(self, subject, public_key, **kwargs):
        now = time.time()
        not_before = kwargs.get('not_before', now - 1.0)
        not_after = kwargs.get('not_after', now + self.default_lifetime)
        cert = {
            'version': 1,
            'issuer': self.issuer,
            'subject': subject,
            'public_key': self._public_key_repr(public_key),
            'not_before': not_before,
            'not_after': not_after,
            'prototype': True,
        }
        cert['signature'] = self._sign_cert_body(cert)
        return cert

    def verify_cert(self, cert, **kwargs):
        if isinstance(cert, str):
            # Compatibility with older benchmark scripts.
            return len(cert) > 0
        if not isinstance(cert, dict):
            return False
        now = kwargs.get('now', time.time())
        required = (
            'version',
            'issuer',
            'subject',
            'public_key',
            'not_before',
            'not_after',
            'signature',
        )
        if not all(field in cert for field in required):
            return False
        if cert.get('version') != 1:
            return False
        if cert.get('issuer') != self.issuer:
            return False
        if now < cert['not_before'] or now > cert['not_after']:
            return False
        if not (cert['subject'] and cert['public_key'] and cert['signature']):
            return False

        public_key = kwargs.get('public_key')
        if public_key is not None and self._public_key_repr(public_key) != cert['public_key']:
            return False

        return self._verify_cert_signature(cert)

    def _sign_cert_body(self, cert):
        body = self._cert_body(cert)
        if self.signature is not None:
            return {
                'alg': self.signature.__class__.__name__,
                'value': self.signature.sign(self.ca_sk, body),
            }
        payload = self._stable_json(body).encode('utf-8')
        return {
            'alg': 'prototype-sha256',
            'value': hashlib.sha256(b'dacp::cert::' + payload).hexdigest(),
        }

    def _verify_cert_signature(self, cert):
        signature = cert.get('signature')
        if not isinstance(signature, dict) or 'alg' not in signature or 'value' not in signature:
            return False
        body = self._cert_body(cert)
        if self.signature is not None:
            return self.signature.verify(self.ca_pk, body, signature['value'])
        payload = self._stable_json(body).encode('utf-8')
        expected = hashlib.sha256(b'dacp::cert::' + payload).hexdigest()
        return signature.get('alg') == 'prototype-sha256' and signature.get('value') == expected

    def _cert_body(self, cert):
        return {
            'version': cert.get('version'),
            'issuer': cert.get('issuer'),
            'subject': cert.get('subject'),
            'public_key': cert.get('public_key'),
            'not_before': cert.get('not_before'),
            'not_after': cert.get('not_after'),
            'prototype': cert.get('prototype', True),
        }

    def _public_key_repr(self, public_key):
        if self.signature is not None and hasattr(self.signature, 'serialize_public_key'):
            try:
                return self.signature.serialize_public_key(public_key).hex()
            except Exception:
                pass
        if isinstance(public_key, bytes):
            return public_key.hex()
        if isinstance(public_key, bytearray):
            return bytes(public_key).hex()
        return str(public_key)

    def _stable_json(self, value):
        return json.dumps(value, sort_keys=True, separators=(',', ':'))
