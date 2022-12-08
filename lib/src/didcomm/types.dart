import '../util/types.dart';

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

enum DidcommProtocol {
  issueCredential,
  presentProof,
  discoverFeature,
  invitation,
  requestPresentation
}

extension DidcommProtocolsExt on DidcommProtocol {
  static const Map<DidcommProtocol, String> values = {
    DidcommProtocol.issueCredential: 'issue-credential',
    DidcommProtocol.presentProof: 'present-proof',
    DidcommProtocol.discoverFeature: 'discover-features',
    DidcommProtocol.invitation: 'invitation'
  };
  String get value => values[this]!;
}

enum DidcommMessages {
  proposeCredential,
  offerCredential,
  requestCredential,
  issueCredential,
  previewCredential,
  emptyMessage,
  presentation,
  requestPresentation,
  proposePresentation,
  discoverFeatureQuery,
  discoverFeatureDisclose,
  invitation,
  problemReport;

  // gets the enum type by its descriptive name will throw
  // a [StateError] if it was not found
  DidcommMessages byName(String name) {
    return DidcommMessages.values
        .firstWhere((element) => element.value == name);
  }
}

extension DidcommMessagesExt on DidcommMessages {
  static const Map<DidcommMessages, String> values = {
    DidcommMessages.proposeCredential:
        'https://didcomm.org/issue-credential/3.0/propose-credential',
    DidcommMessages.offerCredential:
        'https://didcomm.org/issue-credential/3.0/offer-credential',
    DidcommMessages.requestCredential:
        'https://didcomm.org/issue-credential/3.0/request-credential',
    DidcommMessages.issueCredential:
        'https://didcomm.org/issue-credential/3.0/issue-credential',
    DidcommMessages.previewCredential:
        'https://didcomm.org/issue-credential/3.0/credential-preview',
    DidcommMessages.emptyMessage: 'https://didcomm.org/empty/1.0',
    DidcommMessages.presentation:
        'https://didcomm.org/present-proof/3.0/presentation',
    DidcommMessages.requestPresentation:
        'https://didcomm.org/present-proof/3.0/request-presentation',
    DidcommMessages.proposePresentation:
        'https://didcomm.org/present-proof/3.0/propose-presentation',
    DidcommMessages.discoverFeatureQuery:
        'https://didcomm.org/discover-features/2.0/queries',
    DidcommMessages.discoverFeatureDisclose:
        'https://didcomm.org/discover-features/1.0/disclose',
    DidcommMessages.invitation:
        'https://didcomm.org/out-of-band/2.0/invitation',
    DidcommMessages.problemReport:
        'https://didcomm.org/report-problem/2.0/problem-report'
  };
  String get value => values[this]!;
  List<String> get allValues => values.values.toList();
}

enum AttachmentFormat {
  presentationDefinition,
  presentationDefinition2,
  presentationSubmission,
  presentationSubmission2,
  ldProofVc,
  ldProofVcDetail,
  credentialManifestAries,
  credentialManifest,
  credentialFulfillment,
  credentialApplication,
  indyProofRequest,
  indyProof,
  indyCredential,
  indyCredentialRequest,
  indyCredentialAbstract,
  indyCredentialFilter
}

extension AttachmentFormatExt on AttachmentFormat {
  static const Map<AttachmentFormat, String> values = {
    AttachmentFormat.presentationDefinition:
        'dif/presentation-exchange/definitions@v1.0',
    AttachmentFormat.presentationDefinition2:
        'dif/presentation-exchange/definitions@v2.0',
    AttachmentFormat.presentationSubmission:
        'dif/presentation-exchange/submission@v1.0',
    AttachmentFormat.presentationSubmission2:
        'dif/presentation-exchange/submission@v2.0',
    AttachmentFormat.ldProofVc: 'aries/ld-proof-vc@v1.0',
    AttachmentFormat.ldProofVcDetail: 'aries/ld-proof-vc-detail@v1.0',
    AttachmentFormat.credentialManifestAries: 'dif/credential-manifest@v1.0',
    AttachmentFormat.credentialManifest:
        'dif/credential-manifest/manifest@v1.0',
    AttachmentFormat.credentialFulfillment:
        'dif/credential-manifest/fulfillment@v1.0',
    AttachmentFormat.credentialApplication:
        'dif/credential-manifest/application@v1.0',
    AttachmentFormat.indyProofRequest: 'hlindy/proof-req@v2.0',
    AttachmentFormat.indyProof: 'hlindy/proof@v2.0',
    AttachmentFormat.indyCredential: 'hlindy/cred@v2.0',
    AttachmentFormat.indyCredentialRequest: 'hlindy/cred-req@v2.0',
    AttachmentFormat.indyCredentialAbstract: 'hlindy/cred-abstract@v2.0',
    AttachmentFormat.indyCredentialFilter: 'hlindy/cred-filter@v2.0'
  };
  String get value => values[this]!;
  List<String> get allValues => values.values.toList();
}

enum AcknowledgeStatus { ok, fail, pending }

extension AcknowledgeStatusExt on AcknowledgeStatus {
  static const Map<AcknowledgeStatus, String> values = {
    AcknowledgeStatus.ok: 'OK',
    AcknowledgeStatus.pending: 'PENDING',
    AcknowledgeStatus.fail: 'FAIL'
  };
  String get value => values[this]!;
}
