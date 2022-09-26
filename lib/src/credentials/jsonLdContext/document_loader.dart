import 'package:json_ld_processor/json_ld_processor.dart';

import 'credentials_v1.dart';
import 'ecdsa_recovery_2020.dart';
import 'ed25519_Signature.dart';
import 'presentation_submission_context.dart';
import 'schema_org.dart';

RemoteDocument loadDocumentStrict(Uri url, LoadDocumentOptions? options) {
  if (url.toString() == CREDENTIALS_V1_IRI) {
    return RemoteDocument(document: CREDENTIALS_V1);
  } else if (url.toString() == ECDSA_RECOVERY_CONTEXT_IRI) {
    return RemoteDocument(document: ECDSA_RECOVERY_SIGNATURE_2020);
  } else if (url.toString() == ED25519_SIGNATURE_CONTEXT_IRI) {
    return RemoteDocument(document: ED25519_SIGNATURE);
  } else if (url.toString().contains('schema.org')) {
    return RemoteDocument(document: SCHEMA_ORG);
  } else if (url.toString() == PRESENTATION_SUBMISSION_IRI) {
    return RemoteDocument(document: PRESENTATION_SUBMISSION_CONTEXT);
  } else {
    throw JsonLdError('Document loading failed: could not find $url locally');
  }
}
