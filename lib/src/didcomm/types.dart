import '../util/types.dart';

enum DidcommProfiles {
  aip1,
  rfc19,
  rfc587,
  v2;

  static const Map<DidcommProfiles, String> stringValues = {
    DidcommProfiles.aip1: 'didcomm/aip1',
    DidcommProfiles.rfc19: 'didcomm/aip2;env=rfc19',
    DidcommProfiles.rfc587: 'didcomm/aip2;env=rfc587',
    DidcommProfiles.v2: 'didcomm/v2'
  };
  String get value => stringValues[this]!;
}

enum DidcommMessageTyp {
  plain,
  signed,
  encrypted;

  static const Map<DidcommMessageTyp, String> stringValues = {
    DidcommMessageTyp.plain: 'application/didcomm-plain+json',
    DidcommMessageTyp.signed: 'application/didcomm-signed+json',
    DidcommMessageTyp.encrypted: 'application/didcomm-encrypted+json'
  };
  String get value => stringValues[this]!;
}

abstract class DidcommMessage implements JsonObject {}

/// Combination of Key-Wrap and Key agreement algorithm
enum KeyWrapAlgorithm {
  ecdhES,
  ecdh1PU;

  static const Map<KeyWrapAlgorithm, String> stringValues = {
    KeyWrapAlgorithm.ecdhES: 'ECDH-ES+A256KW',
    KeyWrapAlgorithm.ecdh1PU: 'ECDH-1PU+A256KW',
  };
  String get value => stringValues[this]!;
}

enum EncryptionAlgorithm {
  a256cbc,
  a256gcm;

  static const Map<EncryptionAlgorithm, String> stringValues = {
    EncryptionAlgorithm.a256cbc: 'A256CBC-HS512',
    EncryptionAlgorithm.a256gcm: 'A256GCM',
  };
  String get value => stringValues[this]!;
}

enum JwsSignatureAlgorithm {
  edDsa,
  es256,
  es256k;

  static const Map<JwsSignatureAlgorithm, String> stringValues = {
    JwsSignatureAlgorithm.edDsa: 'EdDSA',
    JwsSignatureAlgorithm.es256: 'ES256',
    JwsSignatureAlgorithm.es256k: 'ES256K'
  };
  String get value => stringValues[this]!;
}

enum DidcommProtocol {
  issueCredential,
  presentProof,
  discoverFeature,
  invitation,
  requestPresentation;

  static const Map<DidcommProtocol, String> stringValues = {
    DidcommProtocol.issueCredential: 'issue-credential',
    DidcommProtocol.presentProof: 'present-proof',
    DidcommProtocol.discoverFeature: 'discover-features',
    DidcommProtocol.invitation: 'invitation'
  };
  String get value => stringValues[this]!;
}

class DidcommMessages {
  static const String proposeCredential =
      'https://didcomm.org/issue-credential/3.0/propose-credential';

  static const offerCredential =
      'https://didcomm.org/issue-credential/3.0/offer-credential';

  static const requestCredential =
      'https://didcomm.org/issue-credential/3.0/request-credential';

  static const issueCredential =
      'https://didcomm.org/issue-credential/3.0/issue-credential';

  static const previewCredential =
      'https://didcomm.org/issue-credential/3.0/credential-preview';

  static const emptyMessage = 'https://didcomm.org/empty/1.0';

  static const presentation =
      'https://didcomm.org/present-proof/3.0/presentation';

  static const requestPresentation =
      'https://didcomm.org/present-proof/3.0/request-presentation';

  static const proposePresentation =
      'https://didcomm.org/present-proof/3.0/propose-presentation';

  static const discoverFeatureQuery =
      'https://didcomm.org/discover-features/2.0/queries';

  static const discoverFeatureDisclose =
      'https://didcomm.org/discover-features/1.0/disclose';

  static const invitation = 'https://didcomm.org/out-of-band/2.0/invitation';

  static const problemReport =
      'https://didcomm.org/report-problem/2.0/problem-report';

  List<String> get allValues => [
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
        problemReport
      ];
}

class AttachmentFormat {
  static const presentationDefinition =
      'dif/presentation-exchange/definitions@v1.0';
  static const presentationDefinition2 =
      'dif/presentation-exchange/definitions@v2.0';
  static const presentationSubmission =
      'dif/presentation-exchange/submission@v1.0';
  static const presentationSubmission2 =
      'dif/presentation-exchange/submission@v2.0';
  static const ldProofVc = 'aries/ld-proof-vc@v1.0';
  static const ldProofVcDetail = 'aries/ld-proof-vc-detail@v1.0';
  static const credentialManifestAries = 'dif/credential-manifest@v1.0';
  static const credentialManifest = 'dif/credential-manifest/manifest@v1.0';
  static const credentialFulfillment =
      'dif/credential-manifest/fulfillment@v1.0';
  static const credentialApplication =
      'dif/credential-manifest/application@v1.0';
  static const indyProofRequest = 'hlindy/proof-req@v2.0';
  static const indyProof = 'hlindy/proof@v2.0';
  static const indyCredential = 'hlindy/cred@v2.0';
  static const indyCredentialRequest = 'hlindy/cred-req@v2.0';
  static const indyCredentialAbstract = 'hlindy/cred-abstract@v2.0';
  static const indyCredentialFilter = 'hlindy/cred-filter@v2.0';

  List<String> get allValues => [
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
      ];
}

enum AcknowledgeStatus {
  ok,
  fail,
  pending;

  static const Map<AcknowledgeStatus, String> stringValues = {
    AcknowledgeStatus.ok: 'OK',
    AcknowledgeStatus.pending: 'PENDING',
    AcknowledgeStatus.fail: 'FAIL'
  };
  String get value => stringValues[this]!;
}

enum ReturnRouteValue {
  none,
  all,
  thread;

  static const Map<ReturnRouteValue, String> stringValues = {
    ReturnRouteValue.none: 'none',
    ReturnRouteValue.all: 'all',
    ReturnRouteValue.thread: 'thread'
  };
  String get value => stringValues[this]!;
}
