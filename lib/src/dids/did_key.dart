import 'package:base_codecs/base_codecs.dart';
import 'package:dart_ssi/src/util/private_util.dart';

import 'did_document.dart';

DidDocument resolveDidKey(String did) {
  if (!did.startsWith('did:key')) throw Exception('Expected did to start with `did:key`. However `$did` did not');
  var splited = did.split(':');
  if (splited.length != 3) throw Exception('malformed did: `$did`');

  String keyPart = splited[2];
  var multibaseIndicator = keyPart[0];
  keyPart = keyPart.substring(1);

  var context = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://w3id.org/security/suites/x25519-2020/v1"
  ];

  var id = did;

  if (multibaseIndicator != 'z') {
    throw UnimplementedError('Only Base58 is supported yet');
  }
  if (keyPart.startsWith('6Mk')) {
    return _buildEDDoc(context, id, keyPart);
  } else if (keyPart.startsWith('6LS')) {
    return _buildXDoc(context, id, keyPart);
  } else {
    throw UnimplementedError('Only Ed25519 and X25519 keys are supported now');
  }
}

DidDocument _buildEDDoc(List<String> context, String id, String keyPart) {
  var multiCodecXKey =
      ed25519PublicToX25519Public(base58Bitcoin.decode(keyPart).sublist(2));
  if (!multiCodecXKey.startsWith('6LS')) {
    throw Exception(
        'Something went wrong during conversion from Ed25515 to curve25519 key');
  }
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

DidDocument _buildXDoc(List<String> context, String id, String keyPart) {
  String verificationKeyId = '$id#z$keyPart';
  var verification = VerificationMethod(
      id: verificationKeyId,
      controller: id,
      type: 'X25519KeyAgreementKey2020',
      publicKeyMultibase: 'z$keyPart');
  return DidDocument(
      context: context,
      id: id,
      verificationMethod: [verification],
      keyAgreement: [verificationKeyId]);
}
