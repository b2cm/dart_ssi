import 'dart:convert';

import 'package:dart_web3/crypto.dart';
import 'package:elliptic/elliptic.dart' as elliptic;
import 'package:flutter_ssi_wallet/flutter_ssi_wallet.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';
import 'package:x25519/x25519.dart' as x25519;

void main() async {
  var message = DidcommPlaintextMessage.fromJson({
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "from": "did:example:alice",
    "to": ["did:example:bob"],
    "created_time": 1516269022,
    "expires_time": 1516385931,
    "body": {"messagespecificattribute": "and its value"}
  });

  group('with fresh generated Keys', () {
    test('A256GCM with ECDH-ES P-256', () {
      var c = elliptic.getP256();
      var alice = c.generatePrivateKey();
      var bob = c.generatePrivateKey();

      var aliceJWK = {
        'kid': 'did:example:alice',
        'crv': 'P-256',
        'kty': 'EC',
        'd': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.Y)))
      };
      var bobJWK = {
        'kid': 'did:example:bob',
        'crv': 'P-256',
        'kty': 'EC',
        'd':
            removePaddingFromBase64(base64UrlEncode(unsignedIntToBytes(bob.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.Y)))
      };

      var encrypted = DidcommEncryptedMessage.fromPlaintext(
          keyWrapAlgorithm: KeyWrapAlgorithm.ecdhES,
          encryptionAlgorithm: EncryptionAlgorithm.a256gcm,
          senderPrivateKeyJwk: aliceJWK,
          recipientPublicKeyJwk: [bobJWK],
          plaintext: message);
      var m2 = encrypted.decrypt(bobJWK);
      expect(m2 is DidcommPlaintextMessage, true);
      m2 = m2 as DidcommPlaintextMessage;
      expect(message.expiresTime, m2.expiresTime);
      expect(message.body, m2.body);
    });
    test('A256GCM with ECDH-ES P-384', () {
      var c = elliptic.getP384();
      var alice = c.generatePrivateKey();
      var bob = c.generatePrivateKey();

      var aliceJWK = {
        'kid': 'did:example:alice',
        'crv': 'P-384',
        'kty': 'EC',
        'd': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.Y)))
      };
      var bobJWK = {
        'kid': 'did:example:bob',
        'crv': 'P-384',
        'kty': 'EC',
        'd':
            removePaddingFromBase64(base64UrlEncode(unsignedIntToBytes(bob.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.Y)))
      };

      var encrypted = DidcommEncryptedMessage.fromPlaintext(
          keyWrapAlgorithm: KeyWrapAlgorithm.ecdhES,
          encryptionAlgorithm: EncryptionAlgorithm.a256gcm,
          senderPrivateKeyJwk: aliceJWK,
          recipientPublicKeyJwk: [bobJWK],
          plaintext: message);
      var m2 = encrypted.decrypt(bobJWK);
      expect(m2 is DidcommPlaintextMessage, true);
      m2 = m2 as DidcommPlaintextMessage;
      expect(message.expiresTime, m2.expiresTime);
      expect(message.body, m2.body);
    });
    test('A256GCM with ECDH-ES P-521', () {
      var c = elliptic.getP521();
      var alice = c.generatePrivateKey();
      var bob = c.generatePrivateKey();

      var aliceJWK = {
        'kid': 'did:example:alice',
        'crv': 'P-521',
        'kty': 'EC',
        'd': removePaddingFromBase64(base64UrlEncode(alice.bytes)),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.Y)))
      };
      var bobJWK = {
        'kid': 'did:example:bob',
        'crv': 'P-521',
        'kty': 'EC',
        'd': removePaddingFromBase64(base64UrlEncode(bob.bytes)),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.Y)))
      };

      var encrypted = DidcommEncryptedMessage.fromPlaintext(
          keyWrapAlgorithm: KeyWrapAlgorithm.ecdhES,
          encryptionAlgorithm: EncryptionAlgorithm.a256gcm,
          senderPrivateKeyJwk: aliceJWK,
          recipientPublicKeyJwk: [bobJWK],
          plaintext: message);
      var m2 = encrypted.decrypt(bobJWK);
      expect(m2 is DidcommPlaintextMessage, true);
      m2 = m2 as DidcommPlaintextMessage;
      expect(message.expiresTime, m2.expiresTime);
      expect(message.body, m2.body);
    });
    test('A256GCM with ECDH-ES X25519', () {
      var alice = x25519.generateKeyPair();
      var bob = x25519.generateKeyPair();

      var aliceJWK = {
        'kid': 'did:example:alice',
        'crv': 'X25519',
        'kty': 'EC',
        'd': removePaddingFromBase64(base64UrlEncode(alice.privateKey)),
        'x': removePaddingFromBase64(base64UrlEncode(alice.publicKey)),
      };
      var bobJWK = {
        'kid': 'did:example:bob',
        'crv': 'X25519',
        'kty': 'EC',
        'd': removePaddingFromBase64(base64UrlEncode(bob.privateKey)),
        'x': removePaddingFromBase64(base64UrlEncode(bob.publicKey)),
      };

      var encrypted = DidcommEncryptedMessage.fromPlaintext(
          keyWrapAlgorithm: KeyWrapAlgorithm.ecdhES,
          encryptionAlgorithm: EncryptionAlgorithm.a256gcm,
          senderPrivateKeyJwk: aliceJWK,
          recipientPublicKeyJwk: [bobJWK],
          plaintext: message);
      var m2 = encrypted.decrypt(bobJWK);
      expect(m2 is DidcommPlaintextMessage, true);
      m2 = m2 as DidcommPlaintextMessage;
      expect(message.expiresTime, m2.expiresTime);
      expect(message.body, m2.body);
    });

    test('A256GCM with ECDH-1PU P-256', () {
      var c = elliptic.getP256();
      var alice = c.generatePrivateKey();
      var bob = c.generatePrivateKey();

      var aliceJWK = {
        'kid': 'did:example:alice',
        'crv': 'P-256',
        'kty': 'EC',
        'd': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.Y)))
      };
      var bobJWK = {
        'kid': 'did:example:bob',
        'crv': 'P-256',
        'kty': 'EC',
        'd':
            removePaddingFromBase64(base64UrlEncode(unsignedIntToBytes(bob.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.Y)))
      };

      var encrypted = DidcommEncryptedMessage.fromPlaintext(
          encryptionAlgorithm: EncryptionAlgorithm.a256gcm,
          senderPrivateKeyJwk: aliceJWK,
          recipientPublicKeyJwk: [bobJWK],
          plaintext: message);
      var m2 = encrypted.decrypt(bobJWK, aliceJWK);
      expect(m2 is DidcommPlaintextMessage, true);
      m2 = m2 as DidcommPlaintextMessage;
      expect(message.expiresTime, m2.expiresTime);
      expect(message.body, m2.body);
    });
    test('A256GCM with ECDH-1PU P-384', () {
      var c = elliptic.getP384();
      var alice = c.generatePrivateKey();
      var bob = c.generatePrivateKey();

      var aliceJWK = {
        'kid': 'did:example:alice',
        'crv': 'P-384',
        'kty': 'EC',
        'd': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.Y)))
      };
      var bobJWK = {
        'kid': 'did:example:bob',
        'crv': 'P-384',
        'kty': 'EC',
        'd':
            removePaddingFromBase64(base64UrlEncode(unsignedIntToBytes(bob.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.Y)))
      };

      var encrypted = DidcommEncryptedMessage.fromPlaintext(
          encryptionAlgorithm: EncryptionAlgorithm.a256gcm,
          senderPrivateKeyJwk: aliceJWK,
          recipientPublicKeyJwk: [bobJWK],
          plaintext: message);
      var m2 = encrypted.decrypt(bobJWK, aliceJWK);
      expect(m2 is DidcommPlaintextMessage, true);
      m2 = m2 as DidcommPlaintextMessage;
      expect(message.expiresTime, m2.expiresTime);
      expect(message.body, m2.body);
    });
    test('A256GCM with ECDH-1PU P-521', () {
      var c = elliptic.getP521();
      var alice = c.generatePrivateKey();
      var bob = c.generatePrivateKey();

      var aliceJWK = {
        'kid': 'did:example:alice',
        'crv': 'P-521',
        'kty': 'EC',
        'd': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.Y)))
      };
      var bobJWK = {
        'kid': 'did:example:bob',
        'crv': 'P-521',
        'kty': 'EC',
        'd':
            removePaddingFromBase64(base64UrlEncode(unsignedIntToBytes(bob.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.Y)))
      };

      var encrypted = DidcommEncryptedMessage.fromPlaintext(
          encryptionAlgorithm: EncryptionAlgorithm.a256gcm,
          senderPrivateKeyJwk: aliceJWK,
          recipientPublicKeyJwk: [bobJWK],
          plaintext: message);
      var m2 = encrypted.decrypt(bobJWK, aliceJWK);
      expect(m2 is DidcommPlaintextMessage, true);
      m2 = m2 as DidcommPlaintextMessage;
      expect(message.expiresTime, m2.expiresTime);
      expect(message.body, m2.body);
    });
    test('A256GCM with ECDH-1PU X25519', () {
      var alice = x25519.generateKeyPair();
      var bob = x25519.generateKeyPair();

      var aliceJWK = {
        'kid': 'did:example:alice',
        'crv': 'X25519',
        'kty': 'EC',
        'd': removePaddingFromBase64(base64UrlEncode(alice.privateKey)),
        'x': removePaddingFromBase64(base64UrlEncode(alice.publicKey)),
      };
      var bobJWK = {
        'kid': 'did:example:bob',
        'crv': 'X25519',
        'kty': 'EC',
        'd': removePaddingFromBase64(base64UrlEncode(bob.privateKey)),
        'x': removePaddingFromBase64(base64UrlEncode(bob.publicKey)),
      };

      var encrypted = DidcommEncryptedMessage.fromPlaintext(
          encryptionAlgorithm: EncryptionAlgorithm.a256gcm,
          senderPrivateKeyJwk: aliceJWK,
          recipientPublicKeyJwk: [bobJWK],
          plaintext: message);
      var m2 = encrypted.decrypt(bobJWK, aliceJWK);
      expect(m2 is DidcommPlaintextMessage, true);
      m2 = m2 as DidcommPlaintextMessage;
      expect(message.expiresTime, m2.expiresTime);
      expect(message.body, m2.body);
    });

    test('A256CBC-HS512 with ECDH-ES P-256', () {
      var c = elliptic.getP256();
      var alice = c.generatePrivateKey();
      var bob = c.generatePrivateKey();

      var aliceJWK = {
        'kid': 'did:example:alice',
        'crv': 'P-256',
        'kty': 'EC',
        'd': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.Y)))
      };
      var bobJWK = {
        'kid': 'did:example:bob',
        'crv': 'P-256',
        'kty': 'EC',
        'd':
            removePaddingFromBase64(base64UrlEncode(unsignedIntToBytes(bob.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.Y)))
      };

      var encrypted = DidcommEncryptedMessage.fromPlaintext(
          keyWrapAlgorithm: KeyWrapAlgorithm.ecdhES,
          senderPrivateKeyJwk: aliceJWK,
          recipientPublicKeyJwk: [bobJWK],
          plaintext: message);
      var m2 = encrypted.decrypt(bobJWK);
      expect(m2 is DidcommPlaintextMessage, true);
      m2 = m2 as DidcommPlaintextMessage;
      expect(message.expiresTime, m2.expiresTime);
      expect(message.body, m2.body);
    });
    test('A256CBC-HS512 with ECDH-ES P-384', () {
      var c = elliptic.getP384();
      var alice = c.generatePrivateKey();
      var bob = c.generatePrivateKey();

      var aliceJWK = {
        'kid': 'did:example:alice',
        'crv': 'P-384',
        'kty': 'EC',
        'd': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.Y)))
      };
      var bobJWK = {
        'kid': 'did:example:bob',
        'crv': 'P-384',
        'kty': 'EC',
        'd':
            removePaddingFromBase64(base64UrlEncode(unsignedIntToBytes(bob.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.Y)))
      };

      var encrypted = DidcommEncryptedMessage.fromPlaintext(
          keyWrapAlgorithm: KeyWrapAlgorithm.ecdhES,
          senderPrivateKeyJwk: aliceJWK,
          recipientPublicKeyJwk: [bobJWK],
          plaintext: message);
      var m2 = encrypted.decrypt(bobJWK);
      expect(m2 is DidcommPlaintextMessage, true);
      m2 = m2 as DidcommPlaintextMessage;
      expect(message.expiresTime, m2.expiresTime);
      expect(message.body, m2.body);
    });
    test('A256CBC-HS512 with ECDH-ES P-521', () {
      var c = elliptic.getP521();
      var alice = c.generatePrivateKey();
      var bob = c.generatePrivateKey();

      var aliceJWK = {
        'kid': 'did:example:alice',
        'crv': 'P-521',
        'kty': 'EC',
        'd': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.Y)))
      };
      var bobJWK = {
        'kid': 'did:example:bob',
        'crv': 'P-521',
        'kty': 'EC',
        'd':
            removePaddingFromBase64(base64UrlEncode(unsignedIntToBytes(bob.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.Y)))
      };

      var encrypted = DidcommEncryptedMessage.fromPlaintext(
          keyWrapAlgorithm: KeyWrapAlgorithm.ecdhES,
          senderPrivateKeyJwk: aliceJWK,
          recipientPublicKeyJwk: [bobJWK],
          plaintext: message);
      var m2 = encrypted.decrypt(bobJWK);
      expect(m2 is DidcommPlaintextMessage, true);
      m2 = m2 as DidcommPlaintextMessage;
      expect(message.expiresTime, m2.expiresTime);
      expect(message.body, m2.body);
    });
    test('A256CBC-HS512 with ECDH-ES X25519', () {
      var alice = x25519.generateKeyPair();
      var bob = x25519.generateKeyPair();

      var aliceJWK = {
        'kid': 'did:example:alice',
        'crv': 'X25519',
        'kty': 'EC',
        'd': removePaddingFromBase64(base64UrlEncode(alice.privateKey)),
        'x': removePaddingFromBase64(base64UrlEncode(alice.publicKey)),
      };
      var bobJWK = {
        'kid': 'did:example:bob',
        'crv': 'X25519',
        'kty': 'EC',
        'd': removePaddingFromBase64(base64UrlEncode(bob.privateKey)),
        'x': removePaddingFromBase64(base64UrlEncode(bob.publicKey)),
      };

      var encrypted = DidcommEncryptedMessage.fromPlaintext(
          keyWrapAlgorithm: KeyWrapAlgorithm.ecdhES,
          senderPrivateKeyJwk: aliceJWK,
          recipientPublicKeyJwk: [bobJWK],
          plaintext: message);
      var m2 = encrypted.decrypt(bobJWK);
      expect(m2 is DidcommPlaintextMessage, true);
      m2 = m2 as DidcommPlaintextMessage;
      expect(message.expiresTime, m2.expiresTime);
      expect(message.body, m2.body);
    });

    test('A256CBC-HS512 with ECDH-1PU P-256', () {
      var c = elliptic.getP256();
      var alice = c.generatePrivateKey();
      var bob = c.generatePrivateKey();

      var aliceJWK = {
        'kid': 'did:example:alice',
        'crv': 'P-256',
        'kty': 'EC',
        'd': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.Y)))
      };
      var bobJWK = {
        'kid': 'did:example:bob',
        'crv': 'P-256',
        'kty': 'EC',
        'd':
            removePaddingFromBase64(base64UrlEncode(unsignedIntToBytes(bob.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.Y)))
      };

      var encrypted = DidcommEncryptedMessage.fromPlaintext(
          senderPrivateKeyJwk: aliceJWK,
          recipientPublicKeyJwk: [bobJWK],
          plaintext: message);
      var m2 = encrypted.decrypt(bobJWK, aliceJWK);
      expect(m2 is DidcommPlaintextMessage, true);
      m2 = m2 as DidcommPlaintextMessage;
      expect(message.expiresTime, m2.expiresTime);
      expect(message.body, m2.body);
    });
    test('A256CBC-HS512 with ECDH-1PU P-384', () {
      var c = elliptic.getP384();
      var alice = c.generatePrivateKey();
      var bob = c.generatePrivateKey();

      var aliceJWK = {
        'kid': 'did:example:alice',
        'crv': 'P-384',
        'kty': 'EC',
        'd': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.Y)))
      };
      var bobJWK = {
        'kid': 'did:example:bob',
        'crv': 'P-384',
        'kty': 'EC',
        'd':
            removePaddingFromBase64(base64UrlEncode(unsignedIntToBytes(bob.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.Y)))
      };

      var encrypted = DidcommEncryptedMessage.fromPlaintext(
          senderPrivateKeyJwk: aliceJWK,
          recipientPublicKeyJwk: [bobJWK],
          plaintext: message);
      var m2 = encrypted.decrypt(bobJWK, aliceJWK);
      expect(m2 is DidcommPlaintextMessage, true);
      m2 = m2 as DidcommPlaintextMessage;
      expect(message.expiresTime, m2.expiresTime);
      expect(message.body, m2.body);
    });
    test('A256CBC-HS512 with ECDH-1PU P-521', () {
      var c = elliptic.getP521();
      var alice = c.generatePrivateKey();
      var bob = c.generatePrivateKey();

      var aliceJWK = {
        'kid': 'did:example:alice',
        'crv': 'P-521',
        'kty': 'EC',
        'd': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(alice.publicKey.Y)))
      };
      var bobJWK = {
        'kid': 'did:example:bob',
        'crv': 'P-521',
        'kty': 'EC',
        'd':
            removePaddingFromBase64(base64UrlEncode(unsignedIntToBytes(bob.D))),
        'x': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.X))),
        'y': removePaddingFromBase64(
            base64UrlEncode(unsignedIntToBytes(bob.publicKey.Y)))
      };

      var encrypted = DidcommEncryptedMessage.fromPlaintext(
          senderPrivateKeyJwk: aliceJWK,
          recipientPublicKeyJwk: [bobJWK],
          plaintext: message);
      var m2 = encrypted.decrypt(bobJWK, aliceJWK);
      expect(m2 is DidcommPlaintextMessage, true);
      m2 = m2 as DidcommPlaintextMessage;
      expect(message.expiresTime, m2.expiresTime);
      expect(message.body, m2.body);
    });
    test('A256CBC-HS512 with ECDH-1PU X25519', () {
      var alice = x25519.generateKeyPair();
      var bob = x25519.generateKeyPair();

      var aliceJWK = {
        'kid': 'did:example:alice',
        'crv': 'X25519',
        'kty': 'EC',
        'd': removePaddingFromBase64(base64UrlEncode(alice.privateKey)),
        'x': removePaddingFromBase64(base64UrlEncode(alice.publicKey)),
      };
      var bobJWK = {
        'kid': 'did:example:bob',
        'crv': 'X25519',
        'kty': 'EC',
        'd': removePaddingFromBase64(base64UrlEncode(bob.privateKey)),
        'x': removePaddingFromBase64(base64UrlEncode(bob.publicKey)),
      };

      var encrypted = DidcommEncryptedMessage.fromPlaintext(
          senderPrivateKeyJwk: aliceJWK,
          recipientPublicKeyJwk: [bobJWK],
          plaintext: message);
      var m2 = encrypted.decrypt(bobJWK, aliceJWK);
      expect(m2 is DidcommPlaintextMessage, true);
      m2 = m2 as DidcommPlaintextMessage;
      expect(message.expiresTime, m2.expiresTime);
      expect(message.body, m2.body);
    });
  });

  group('example form didcomm-Spec', () {
    test(
        'example2 ECDH-ES / A256CBC-HS512 decrypt with did:example:bob#key-p384-1',
        () {
      var encrypted = DidcommEncryptedMessage.fromJson({
        "ciphertext":
            "HPnc9w7jK0T73Spifq_dcVJnONbT9MZ9oorDJFEBJAfmwYRqvs1rKue-udrNLTTH0qjjbeuji01xPRF5JiWyy-gSMX4LHdLhPxHxjjQCTkThY0kapofU85EjLPlI4ytbHiGcrPIezqCun4iDkmb50pwiLvL7XY1Ht6zPUUdhiV6qWoPP4qeY_8pfH74Q5u7K4TQ0uU3KP8CVZQuafrkOBbqbqpJV-lWpWIKxil44f1IT_GeIpkWvmkYxTa1MxpYBgOYa5_AUxYBumcIFP-b6g7GQUbN-1SOoP76EzxZU_louspzQ2HdEH1TzXw2LKclN8GdxD7kB0H6lZbZLT3ScDzSVSbvO1w1fXHXOeOzywuAcismmoEXQGbWZm7wJJJ2r",
        "protected":
            "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTM4NCIsIngiOiIxNjFhZ0dlYWhHZW1IZ25qSG1RX0JfU09OeUJWZzhWTGRoVGdWNVc1NFZiYWJ5bGxpc3NuWjZXNzc5SW9VcUtyIiwieSI6ImNDZXFlRmdvYm9fY1ItWTRUc1pCWlg4dTNCa2l5TnMyYi12ZHFPcU9MeUNuVmdPMmpvN25zQV9JQzNhbnQ5T1gifSwiYXB2IjoiTEpBOUVva3M1dGFtVUZWQmFsTXdCaEo2RGtEY0o4SEs0U2xYWldxRHFubyIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiRUNESC1FUytBMjU2S1cifQ",
        "recipients": [
          {
            "encrypted_key":
                "SlyWCiOaHMMH9CqSs2CHpRd2XwbueZ1-MfYgKVepXWpgmTgtsgNOAaYwV5pxK3D67HV51F-vLBFlAHke7RYp_GeGDFYhAf5s",
            "header": {"kid": "did:example:bob#key-p384-1"}
          },
          {
            "encrypted_key":
                "5e7ChtaRgIlV4yS4NSD7kEo0iJfFmL_BFgRh3clDKBG_QoPd1eOtFlTxFJh-spE0khoaw8vEEYTcQIg4ReeFT3uQ8aayz1oY",
            "header": {"kid": "did:example:bob#key-p384-2"}
          }
        ],
        "tag": "bkodXkuuwRbqksnQNsCM2YLy9f0v0xNgnhSUAoFGtmE",
        "iv": "aE1XaH767m7LY0JTN7RsAA"
      });

      var bobKeyJWK = {
        "kid": "did:example:bob#key-p384-1",
        "kty": "EC",
        "d": "ajqcWbYA0UDBKfAhkSkeiVjMMt8l-5rcknvEv9t_Os6M8s-HisdywvNCX4CGd_xY",
        "crv": "P-384",
        "x": "MvnE_OwKoTcJVfHyTX-DLSRhhNwlu5LNoQ5UWD9Jmgtdxp_kpjsMuTTBnxg5RF_Y",
        "y": "X_3HJBcKFQEG35PZbEOBn8u9_z8V1F9V1Kv-Vh0aSzmH-y9aOuDJUE3D4Hvmi5l7"
      };

      var m = encrypted.decrypt(bobKeyJWK);
      expect(m is DidcommPlaintextMessage, true);
      m = m as DidcommPlaintextMessage;
      expect(message.expiresTime, m.expiresTime);
      expect(message.body, m.body);
    });

    test(
        'example2 ECDH-ES / A256CBC-HS512 decrypt with did:example:bob#key-p384-2',
        () {
      var encrypted = DidcommEncryptedMessage.fromJson({
        "ciphertext":
            "HPnc9w7jK0T73Spifq_dcVJnONbT9MZ9oorDJFEBJAfmwYRqvs1rKue-udrNLTTH0qjjbeuji01xPRF5JiWyy-gSMX4LHdLhPxHxjjQCTkThY0kapofU85EjLPlI4ytbHiGcrPIezqCun4iDkmb50pwiLvL7XY1Ht6zPUUdhiV6qWoPP4qeY_8pfH74Q5u7K4TQ0uU3KP8CVZQuafrkOBbqbqpJV-lWpWIKxil44f1IT_GeIpkWvmkYxTa1MxpYBgOYa5_AUxYBumcIFP-b6g7GQUbN-1SOoP76EzxZU_louspzQ2HdEH1TzXw2LKclN8GdxD7kB0H6lZbZLT3ScDzSVSbvO1w1fXHXOeOzywuAcismmoEXQGbWZm7wJJJ2r",
        "protected":
            "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTM4NCIsIngiOiIxNjFhZ0dlYWhHZW1IZ25qSG1RX0JfU09OeUJWZzhWTGRoVGdWNVc1NFZiYWJ5bGxpc3NuWjZXNzc5SW9VcUtyIiwieSI6ImNDZXFlRmdvYm9fY1ItWTRUc1pCWlg4dTNCa2l5TnMyYi12ZHFPcU9MeUNuVmdPMmpvN25zQV9JQzNhbnQ5T1gifSwiYXB2IjoiTEpBOUVva3M1dGFtVUZWQmFsTXdCaEo2RGtEY0o4SEs0U2xYWldxRHFubyIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiRUNESC1FUytBMjU2S1cifQ",
        "recipients": [
          {
            "encrypted_key":
                "SlyWCiOaHMMH9CqSs2CHpRd2XwbueZ1-MfYgKVepXWpgmTgtsgNOAaYwV5pxK3D67HV51F-vLBFlAHke7RYp_GeGDFYhAf5s",
            "header": {"kid": "did:example:bob#key-p384-1"}
          },
          {
            "encrypted_key":
                "5e7ChtaRgIlV4yS4NSD7kEo0iJfFmL_BFgRh3clDKBG_QoPd1eOtFlTxFJh-spE0khoaw8vEEYTcQIg4ReeFT3uQ8aayz1oY",
            "header": {"kid": "did:example:bob#key-p384-2"}
          }
        ],
        "tag": "bkodXkuuwRbqksnQNsCM2YLy9f0v0xNgnhSUAoFGtmE",
        "iv": "aE1XaH767m7LY0JTN7RsAA"
      });

      var bobKeyJWK = {
        "kid": "did:example:bob#key-p384-2",
        "kty": "EC",
        "d": "OiwhRotK188BtbQy0XBO8PljSKYI6CCD-nE_ZUzK7o81tk3imDOuQ-jrSWaIkI-T",
        "crv": "P-384",
        "x": "2x3HOTvR8e-Tu6U4UqMd1wUWsNXMD0RgIunZTMcZsS-zWOwDgsrhYVHmv3k_DjV3",
        "y": "W9LLaBjlWYcXUxOf6ECSfcXKaC3-K9z4hCoP0PS87Q_4ExMgIwxVCXUEB6nf0GDd"
      };

      var m = encrypted.decrypt(bobKeyJWK);
      expect(m is DidcommPlaintextMessage, true);
      m = m as DidcommPlaintextMessage;
      expect(message.expiresTime, m.expiresTime);
      expect(message.body, m.body);
    });

    test('example3 ECDH-ES / A256GCM decrypt with did:example:bob#key-p521-1',
        () {
      var encrypted = DidcommEncryptedMessage.fromJson({
        "ciphertext":
            "mxnFl4s8FRsIJIBVcRLv4gj4ru5R0H3BdvyBWwXV3ILhtl_moqzx9COINGomP4ueuApuY5xdMDvRHm2mLo6N-763wjNSjAibNrqVZC-EG24jjYk7RPZ26fEW4z87LHuLTicYCD4yHqilRbRgbOCT0Db5221Kec0HDZTXLzBqVwC2UMyDF4QT6Uz3fE4f_6BXTwjD-sEgM67wWTiWbDJ3Q6WyaOL3W4ukYANDuAR05-SXVehnd3WR0FOg1hVcNRao5ekyWZw4Z2ekEB1JRof3Lh6uq46K0KXpe9Pc64UzAxEID93SoJ0EaV_Sei8CXw2aJFmZUuCf8YISWKUz6QZxRvFKUfYeflldUm9U2tY96RicWgUhuXgv",
        "protected":
            "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTUyMSIsIngiOiJBRWtrc09abW1oZkZYdU90MHMybVdFYlVybVQ3OXc1SFRwUm9TLTZZNXpkYlk5T0I5b2RHb2hDYm1PeGpqY2VhWUU5ZnNaX3RaNmdpTGFBNUFEUnBrWE5VIiwieSI6IkFDaWJnLXZEMmFHVEpHbzlmRUl6Q1dXT2hSVUlObFg3Q1hGSTJqeDlKVDZmTzJfMGZ3SzM2WTctNHNUZTRpRVVSaHlnU1hQOW9TVFczTkdZTXVDMWlPQ3AifSwiYXB2IjoiR09lbzc2eW02TkNnOVdXTUVZZlcwZVZEVDU2Njh6RWhsMnVBSVctRS1IRSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiRUNESC1FUytBMjU2S1cifQ",
        "recipients": [
          {
            "encrypted_key":
                "W4KOy5W88iPPsDEdhkJN2krZ2QAeDxOIxW-4B21H9q89SHWexocCrw",
            "header": {"kid": "did:example:bob#key-p521-1"}
          },
          {
            "encrypted_key":
                "uxKPkF6-sIiEkdeJcUPJY4lvsRg_bvtLPIn7eIycxLJML2KM6-Llag",
            "header": {"kid": "did:example:bob#key-p521-2"}
          }
        ],
        "tag": "aPZeYfwht2Nx9mfURv3j3g",
        "iv": "lGKCvg2xrvi8Qa_D"
      });

      var bobKeyJWK = {
        "kid": "did:example:bob#key-p521-1",
        "kty": "EC",
        "d":
            "AV5ocjvy7PkPgNrSuvCxtG70NMj6iTabvvjSLbsdd8OdI9HlXYlFR7RdBbgLUTruvaIRhjEAE9gNTH6rWUIdfuj6",
        "crv": "P-521",
        "x":
            "Af9O5THFENlqQbh2Ehipt1Yf4gAd9RCa3QzPktfcgUIFADMc4kAaYVViTaDOuvVS2vMS1KZe0D5kXedSXPQ3QbHi",
        "y":
            "ATZVigRQ7UdGsQ9j-omyff6JIeeUv3CBWYsZ0l6x3C_SYqhqVV7dEG-TafCCNiIxs8qeUiXQ8cHWVclqkH4Lo1qH"
      };

      var m = encrypted.decrypt(bobKeyJWK);
      expect(m is DidcommPlaintextMessage, true);
      m = m as DidcommPlaintextMessage;
      expect(message.expiresTime, m.expiresTime);
      expect(message.body, m.body);
    });

    test('example3 ECDH-ES / A256GCM decrypt with did:example:bob#key-p521-2',
        () {
      var encrypted = DidcommEncryptedMessage.fromJson({
        "ciphertext":
            "mxnFl4s8FRsIJIBVcRLv4gj4ru5R0H3BdvyBWwXV3ILhtl_moqzx9COINGomP4ueuApuY5xdMDvRHm2mLo6N-763wjNSjAibNrqVZC-EG24jjYk7RPZ26fEW4z87LHuLTicYCD4yHqilRbRgbOCT0Db5221Kec0HDZTXLzBqVwC2UMyDF4QT6Uz3fE4f_6BXTwjD-sEgM67wWTiWbDJ3Q6WyaOL3W4ukYANDuAR05-SXVehnd3WR0FOg1hVcNRao5ekyWZw4Z2ekEB1JRof3Lh6uq46K0KXpe9Pc64UzAxEID93SoJ0EaV_Sei8CXw2aJFmZUuCf8YISWKUz6QZxRvFKUfYeflldUm9U2tY96RicWgUhuXgv",
        "protected":
            "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTUyMSIsIngiOiJBRWtrc09abW1oZkZYdU90MHMybVdFYlVybVQ3OXc1SFRwUm9TLTZZNXpkYlk5T0I5b2RHb2hDYm1PeGpqY2VhWUU5ZnNaX3RaNmdpTGFBNUFEUnBrWE5VIiwieSI6IkFDaWJnLXZEMmFHVEpHbzlmRUl6Q1dXT2hSVUlObFg3Q1hGSTJqeDlKVDZmTzJfMGZ3SzM2WTctNHNUZTRpRVVSaHlnU1hQOW9TVFczTkdZTXVDMWlPQ3AifSwiYXB2IjoiR09lbzc2eW02TkNnOVdXTUVZZlcwZVZEVDU2Njh6RWhsMnVBSVctRS1IRSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiRUNESC1FUytBMjU2S1cifQ",
        "recipients": [
          {
            "encrypted_key":
                "W4KOy5W88iPPsDEdhkJN2krZ2QAeDxOIxW-4B21H9q89SHWexocCrw",
            "header": {"kid": "did:example:bob#key-p521-1"}
          },
          {
            "encrypted_key":
                "uxKPkF6-sIiEkdeJcUPJY4lvsRg_bvtLPIn7eIycxLJML2KM6-Llag",
            "header": {"kid": "did:example:bob#key-p521-2"}
          }
        ],
        "tag": "aPZeYfwht2Nx9mfURv3j3g",
        "iv": "lGKCvg2xrvi8Qa_D"
      });

      var bobKeyJWK = {
        "kid": "did:example:bob#key-p521-2",
        "kty": "EC",
        "d":
            "ABixMEZHsyT7SRw-lY5HxdNOofTZLlwBHwPEJ3spEMC2sWN1RZQylZuvoyOBGJnPxg4-H_iVhNWf_OtgYODrYhCk",
        "crv": "P-521",
        "x":
            "ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
        "y":
            "AEJipR0Dc-aBZYDqN51SKHYSWs9hM58SmRY1MxgXANgZrPaq1EeGMGOjkbLMEJtBThdjXhkS5VlXMkF0cYhZELiH"
      };

      var m = encrypted.decrypt(bobKeyJWK);
      expect(m is DidcommPlaintextMessage, true);
      m = m as DidcommPlaintextMessage;
      expect(message.expiresTime, m.expiresTime);
      expect(message.body, m.body);
    });

    test(
        'example3 ECDH-1PU/ A256CBC-HS512 decrypt with did:example:bob#key-x25519-1',
        () {
      var encrypted = DidcommEncryptedMessage.fromJson({
        "ciphertext":
            "MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
        "protected":
            "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ",
        "recipients": [
          {
            "encrypted_key":
                "o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
            "header": {"kid": "did:example:bob#key-x25519-1"}
          },
          {
            "encrypted_key":
                "rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
            "header": {"kid": "did:example:bob#key-x25519-2"}
          },
          {
            "encrypted_key":
                "aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo",
            "header": {"kid": "did:example:bob#key-x25519-3"}
          }
        ],
        "tag": "uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
        "iv": "o02OXDQ6_-sKz2PX_6oyJg"
      });

      var bobKeyJWK = {
        "kid": "did:example:bob#key-x25519-1",
        "kty": "OKP",
        "d": "b9NnuOCB0hm7YGNvaE9DMhwH_wjZA1-gWD6dA0JWdL0",
        "crv": "X25519",
        "x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E"
      };

      var aliceJwk = {
        "kty": "OKP",
        "crv": "X25519",
        "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
      };

      var m = encrypted.decrypt(bobKeyJWK, aliceJwk);
      expect(m is DidcommPlaintextMessage, true);
      m = m as DidcommPlaintextMessage;
      expect(message.expiresTime, m.expiresTime);
      expect(message.body, m.body);
    });

    test(
        'example3 ECDH-1PU/ A256CBC-HS512 decrypt with did:example:bob#key-x25519-2',
        () {
      var encrypted = DidcommEncryptedMessage.fromJson({
        "ciphertext":
            "MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
        "protected":
            "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ",
        "recipients": [
          {
            "encrypted_key":
                "o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
            "header": {"kid": "did:example:bob#key-x25519-1"}
          },
          {
            "encrypted_key":
                "rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
            "header": {"kid": "did:example:bob#key-x25519-2"}
          },
          {
            "encrypted_key":
                "aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo",
            "header": {"kid": "did:example:bob#key-x25519-3"}
          }
        ],
        "tag": "uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
        "iv": "o02OXDQ6_-sKz2PX_6oyJg"
      });

      var bobKeyJWK = {
        "kid": "did:example:bob#key-x25519-2",
        "kty": "OKP",
        "d": "p-vteoF1gopny1HXywt76xz_uC83UUmrgszsI-ThBKk",
        "crv": "X25519",
        "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM"
      };

      var aliceJwk = {
        "kty": "OKP",
        "crv": "X25519",
        "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
      };

      var m = encrypted.decrypt(bobKeyJWK, aliceJwk);
      expect(m is DidcommPlaintextMessage, true);
      m = m as DidcommPlaintextMessage;
      expect(message.expiresTime, m.expiresTime);
      expect(message.body, m.body);
    });

    test(
        'example3 ECDH-1PU/ A256CBC-HS512 decrypt with did:example:bob#key-x25519-3',
        () {
      var encrypted = DidcommEncryptedMessage.fromJson({
        "ciphertext":
            "MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
        "protected":
            "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ",
        "recipients": [
          {
            "encrypted_key":
                "o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
            "header": {"kid": "did:example:bob#key-x25519-1"}
          },
          {
            "encrypted_key":
                "rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
            "header": {"kid": "did:example:bob#key-x25519-2"}
          },
          {
            "encrypted_key":
                "aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo",
            "header": {"kid": "did:example:bob#key-x25519-3"}
          }
        ],
        "tag": "uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
        "iv": "o02OXDQ6_-sKz2PX_6oyJg"
      });

      var bobKeyJWK = {
        "kid": "did:example:bob#key-x25519-3",
        "kty": "OKP",
        "d": "f9WJeuQXEItkGM8shN4dqFr5fLQLBasHnWZ-8dPaSo0",
        "crv": "X25519",
        "x": "82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY"
      };

      var aliceJwk = {
        "kty": "OKP",
        "crv": "X25519",
        "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
      };

      var m = encrypted.decrypt(bobKeyJWK, aliceJwk);
      expect(m is DidcommPlaintextMessage, true);
      m = m as DidcommPlaintextMessage;
      expect(message.expiresTime, m.expiresTime);
      expect(message.body, m.body);
    });
  });

  group('signing test from didcomm spec', () {
    test('ed25519', () {
      var signedMessage3 = DidcommSignedMessage.fromJson({
        "payload":
            "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures": [
          {
            "protected":
                "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
            "signature":
                "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
            "header": {"kid": "did:example:alice#key-1"}
          }
        ]
      });
      var key3 = {
        "kid": "did:example:alice#key-1",
        "kty": "OKP",
        "d": "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
        "crv": "Ed25519",
        "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
      };
      expect(signedMessage3.verify(key3), true);
    });
    test('es256', () {
      var signedMessage = DidcommSignedMessage.fromJson({
        "payload":
            "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures": [
          {
            "protected":
                "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ",
            "signature":
                "gcW3lVifhyR48mLHbbpnGZQuziskR5-wXf6IoBlpa9SzERfSG9I7oQ9pssmHZwbvJvyMvxskpH5oudw1W3X5Qg",
            "header": {"kid": "did:example:alice#key-2"}
          }
        ]
      });

      var key = {
        "kid": "did:example:alice#key-2",
        "kty": "EC",
        "d": "7TCIdt1rhThFtWcEiLnk_COEjh1ZfQhM4bW2wz-dp4A",
        "crv": "P-256",
        "x": "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
        "y": "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w"
      };
      expect(signedMessage.verify(key), true);
    });
    test('es259k', () {
      var signedMessage2 = DidcommSignedMessage.fromJson({
        "payload":
            "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures": [
          {
            "protected":
                "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTZLIn0",
            "signature":
                "EGjhIcts6tqiJgqtxaTiTY3EUvL-_rLjn9lxaZ4eRUwa1-CS1nknZoyJWbyY5NQnUafWh5nvCtQpdpMyzH3blw",
            "header": {"kid": "did:example:alice#key-3"}
          }
        ]
      });
      var key2 = {
        "kid": "did:example:alice#key-3",
        "kty": "EC",
        "d": "N3Hm1LXA210YVGGsXw_GklMwcLu_bMgnzDese6YQIyA",
        "crv": "secp256k1",
        "x": "aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
        "y": "JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk"
      };
      expect(signedMessage2.verify(key2), true);
    });
  });

  group('Signing message locally', () {
    test('ed25519', () {
      var key3 = {
        "kid": "did:example:alice#key-1",
        "kty": "OKP",
        "d": "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
        "crv": "Ed25519",
        "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
      };
      var sig3 =
          DidcommSignedMessage.sign(payload: message, jwkToSignWith: [key3]);
      expect(sig3.verify(key3), true);
    });
    test('es256', () {
      var key = {
        "kid": "did:example:alice#key-2",
        "kty": "EC",
        "d": "7TCIdt1rhThFtWcEiLnk_COEjh1ZfQhM4bW2wz-dp4A",
        "crv": "P-256",
        "x": "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
        "y": "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w"
      };
      var sig3 =
          DidcommSignedMessage.sign(payload: message, jwkToSignWith: [key]);
      expect(sig3.verify(key), true);
    });
    test('es259k', () {
      var key2 = {
        "kid": "did:example:alice#key-3",
        "kty": "EC",
        "d": "N3Hm1LXA210YVGGsXw_GklMwcLu_bMgnzDese6YQIyA",
        "crv": "secp256k1",
        "x": "aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
        "y": "JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk"
      };
      var sig3 =
          DidcommSignedMessage.sign(payload: message, jwkToSignWith: [key2]);
      expect(sig3.verify(key2), true);
    });
  });

  group('combination', () {
    test('signed in encrypted', () {
      Map<String, dynamic> aliceEncryptionKey = {
        "kid": "did:example:alice#key-x25519-1",
        "kty": "OKP",
        "d": "r-jK2cO3taR8LQnJB1_ikLBTAnOtShJOsHXRUWT-aZA",
        "crv": "X25519",
        "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
      };
      Map<String, dynamic> aliceSigningKey = {
        "kid": "did:example:alice#key-3",
        "kty": "EC",
        "d": "N3Hm1LXA210YVGGsXw_GklMwcLu_bMgnzDese6YQIyA",
        "crv": "secp256k1",
        "x": "aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
        "y": "JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk"
      };
      Map<String, dynamic> bobPublicKey = {
        "kid": "did:example:bob#key-x25519-1",
        "kty": "OKP",
        "d": "b9NnuOCB0hm7YGNvaE9DMhwH_wjZA1-gWD6dA0JWdL0",
        "crv": "X25519",
        "x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E"
      };

      var signedMessage = DidcommSignedMessage.sign(
          payload: message, jwkToSignWith: [aliceSigningKey]);

      expect(signedMessage.verify(aliceSigningKey), true);

      var encrypted = DidcommEncryptedMessage.fromPlaintext(
          senderPrivateKeyJwk: aliceEncryptionKey,
          recipientPublicKeyJwk: [bobPublicKey],
          plaintext: signedMessage);

      var decrypted = encrypted.decrypt(bobPublicKey, aliceEncryptionKey);
      expect(decrypted is DidcommSignedMessage, true);
      decrypted = decrypted as DidcommSignedMessage;

      var jwm = decrypted.payload as DidcommPlaintextMessage;

      expect(jwm.body, message.body);
    });
  });
}
