import 'package:dart_ssi/src/util/types.dart';

enum DidcommProfiles { aip1, rfc19, rfc587, v2 }

extension DidcommProfileExt on DidcommProfiles {
  static const Map<DidcommProfiles, String> values = {
    DidcommProfiles.aip1: 'didcomm/aip1',
    DidcommProfiles.rfc19: 'didcomm/aip2;env=rfc19',
    DidcommProfiles.rfc587: 'didcomm/aip2;env=rfc587',
    DidcommProfiles.v2: 'didcomm/v2'
  };
  String get value => values[this]!;
}

enum DidcommMessageTyp { plain, signed, encrypted }

extension DidcommMessageTypExt on DidcommMessageTyp {
  static const Map<DidcommMessageTyp, String> values = {
    DidcommMessageTyp.plain: 'application/didcomm-plain+json',
    DidcommMessageTyp.signed: 'application/didcomm-signed+json',
    DidcommMessageTyp.encrypted: 'application/didcomm-encrypted+json'
  };
  String get value => values[this]!;
}

abstract class DidcommMessage implements JsonObject {}

/// Combination of Key-Wrap and Key agreement algorithm
enum KeyWrapAlgorithm { ecdhES, ecdh1PU }

extension KeyWrapAlgorithmExt on KeyWrapAlgorithm {
  static const Map<KeyWrapAlgorithm, String> values = {
    KeyWrapAlgorithm.ecdhES: 'ECDH-ES+A256KW',
    KeyWrapAlgorithm.ecdh1PU: 'ECDH-1PU+A256KW',
  };
  String get value => values[this]!;
}

enum EncryptionAlgorithm { a256cbc, a256gcm }

extension EncryptionAgorithmExt on EncryptionAlgorithm {
  static const Map<EncryptionAlgorithm, String> values = {
    EncryptionAlgorithm.a256cbc: 'A256CBC-HS512',
    EncryptionAlgorithm.a256gcm: 'A256GCM',
  };
  String get value => values[this]!;
}

enum JwsSignatureAlgorithm { edDsa, es256, es256k }

extension JwsSignatureAlgorithmExt on JwsSignatureAlgorithm {
  static const Map<JwsSignatureAlgorithm, String> values = {
    JwsSignatureAlgorithm.edDsa: 'EdDSA',
    JwsSignatureAlgorithm.es256: 'ES256',
    JwsSignatureAlgorithm.es256k: 'ES256K'
  };
  String get value => values[this]!;
}
