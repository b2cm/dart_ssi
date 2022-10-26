import 'package:json_ld_processor/json_ld_processor.dart';

import 'credentials_v1.dart';
import 'ecdsa_recovery_2020.dart';
import 'ed25519_signature.dart';
import 'presentation_submission_context.dart';
import 'schema_org.dart';

RemoteDocument loadDocumentStrict(Uri url, LoadDocumentOptions? options) {
  if (url.toString() == credentialsV1Iri) {
    return RemoteDocument(document: credentialsV1Context);
  } else if (url.toString() == ecdsaRecoveryContextIri) {
    return RemoteDocument(document: ecdsaRecoveryContext);
  } else if (url.toString() == ed25519ContextIri) {
    return RemoteDocument(document: ed25519SignatureContext);
  } else if (url.toString().contains('schema.org')) {
    return RemoteDocument(document: schemaOrgContext);
  } else if (url.toString() == presentationSubmissionContextIri) {
    return RemoteDocument(document: presentationSubmissionContext);
  } else {
    throw JsonLdError('Document loading failed: could not find $url locally');
  }
}