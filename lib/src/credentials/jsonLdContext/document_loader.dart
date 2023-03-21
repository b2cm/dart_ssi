import 'package:dart_ssi/credentials.dart';
import 'package:json_ld_processor/json_ld_processor.dart';

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
  } else if (url.toString() == revocationList202ContextIri) {
    return RemoteDocument(document: revocationList202Context);
  } else if (url.toString() == statusList2021ContextIri) {
    return RemoteDocument(document: statusList2021Context);
  } else {
    throw JsonLdError('Document loading failed: could not find $url locally');
  }
}

Future<RemoteDocument> loadDocumentFast(
    Uri url, LoadDocumentOptions? options) async {
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
  } else if (url.toString() == revocationList202ContextIri) {
    return RemoteDocument(document: revocationList202Context);
  } else if (url.toString() == statusList2021ContextIri) {
    return RemoteDocument(document: statusList2021Context);
  } else {
    return await loadDocument(url, options);
  }
}
