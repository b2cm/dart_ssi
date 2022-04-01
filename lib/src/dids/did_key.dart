import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:x25519/src/curve25519.dart' as x25519;

import 'did_document.dart';

const _xMultiCodec = [236, 1];

DidDocument resolveDidKey(String did) {
  if (!did.startsWith('did:key')) throw Exception('Unexpected did');
  var splited = did.split(':');
  if (splited.length != 3) throw Exception('maleformed did');

  String keyPart = splited[2];
  var multibaseIndicator = keyPart[0];
  keyPart = keyPart.substring(1);

  if (multibaseIndicator != 'z')
    throw UnimplementedError('Only Base58 is supported yet');
  if (!keyPart.startsWith('6Mk'))
    throw UnimplementedError('Only Ed25519 keys are supported now');

  var context = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://w3id.org/security/suites/x25519-2020/v1"
  ];

  var id = did;

  var multiCodecXKey =
      _ed25519PublicToX25519Public(base58Bitcoin.decode(keyPart).sublist(2));
  if (!multiCodecXKey.startsWith('6LS'))
    throw Exception(
        'Something went wrong during conversion from Ed25515 to curve25519 key');
  String verificationKeyId = '$id#z$keyPart';
  String agreementKeyId = '$id#z$multiCodecXKey';

  var verification = VerificationMethod(
      id: verificationKeyId,
      controller: id,
      type: 'Ed25519VerificationKey2020',
      publicKeyMultibase: 'z$keyPart');
  var keyAgreement = VerificationMethod(
      id: agreementKeyId,
      controller: id,
      type: 'X25519KeyAgreementKey2020',
      publicKeyMultibase: 'z$multiCodecXKey');

  return DidDocument(
      context: context,
      id: id,
      verificationMethod: [verification, keyAgreement],
      assertionMethod: [verificationKeyId],
      keyAgreement: [agreementKeyId],
      authentication: [verificationKeyId],
      capabilityDelegation: [verificationKeyId],
      capabilityInvocation: [verificationKeyId]);
}

//ported from https://github.com/oasisprotocol/ed25519/blob/master/extra/x25519/x25519.go
String _ed25519PublicToX25519Public(List<int> ed25519Public) {
  var Y = x25519.FieldElement();
  x25519.feFromBytes(Y, ed25519Public);
  var oneMinusY = x25519.FieldElement();
  x25519.FeOne(oneMinusY);
  x25519.FeSub(oneMinusY, oneMinusY, Y);
  x25519.feInvert(oneMinusY, oneMinusY);

  var outX = x25519.FieldElement();
  x25519.FeOne(outX);
  x25519.FeAdd(outX, outX, Y);

  x25519.feMul(outX, outX, oneMinusY);

  var dst = List.filled(32, 0);
  x25519.FeToBytes(dst, outX);

  return base58Bitcoin.encode(Uint8List.fromList(_xMultiCodec + dst));
}
