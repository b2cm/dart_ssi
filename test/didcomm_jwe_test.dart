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
          'ECDH-ES+A256KW', 'A256GCM', aliceJWK, [bobJWK], message);
      var m2 = encrypted.decrypt(bobJWK);
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
          'ECDH-ES+A256KW', 'A256GCM', aliceJWK, [bobJWK], message);
      var m2 = encrypted.decrypt(bobJWK);
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
          'ECDH-ES+A256KW', 'A256GCM', aliceJWK, [bobJWK], message);
      var m2 = encrypted.decrypt(bobJWK);
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
          'ECDH-ES+A256KW', 'A256GCM', aliceJWK, [bobJWK], message);
      var m2 = encrypted.decrypt(bobJWK);
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
          'ECDH-1PU+A256KW', 'A256GCM', aliceJWK, [bobJWK], message);
      var m2 = encrypted.decrypt(bobJWK, aliceJWK);
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
          'ECDH-1PU+A256KW', 'A256GCM', aliceJWK, [bobJWK], message);
      var m2 = encrypted.decrypt(bobJWK, aliceJWK);
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
          'ECDH-1PU+A256KW', 'A256GCM', aliceJWK, [bobJWK], message);
      var m2 = encrypted.decrypt(bobJWK, aliceJWK);
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
          'ECDH-1PU+A256KW', 'A256GCM', aliceJWK, [bobJWK], message);
      var m2 = encrypted.decrypt(bobJWK, aliceJWK);
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
          'ECDH-ES+A256KW', 'A256CBC-HS512', aliceJWK, [bobJWK], message);
      var m2 = encrypted.decrypt(bobJWK);
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
          'ECDH-ES+A256KW', 'A256CBC-HS512', aliceJWK, [bobJWK], message);
      var m2 = encrypted.decrypt(bobJWK);
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
          'ECDH-ES+A256KW', 'A256CBC-HS512', aliceJWK, [bobJWK], message);
      var m2 = encrypted.decrypt(bobJWK);
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
          'ECDH-ES+A256KW', 'A256CBC-HS512', aliceJWK, [bobJWK], message);
      var m2 = encrypted.decrypt(bobJWK);
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
          'ECDH-1PU+A256KW', 'A256CBC-HS512', aliceJWK, [bobJWK], message);
      var m2 = encrypted.decrypt(bobJWK, aliceJWK);
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
          'ECDH-1PU+A256KW', 'A256CBC-HS512', aliceJWK, [bobJWK], message);
      var m2 = encrypted.decrypt(bobJWK, aliceJWK);
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
          'ECDH-1PU+A256KW', 'A256CBC-HS512', aliceJWK, [bobJWK], message);
      var m2 = encrypted.decrypt(bobJWK, aliceJWK);
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
          'ECDH-1PU+A256KW', 'A256CBC-HS512', aliceJWK, [bobJWK], message);
      var m2 = encrypted.decrypt(bobJWK, aliceJWK);
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
      expect(message.expiresTime, m.expiresTime);
      expect(message.body, m.body);
    });
  });
}
