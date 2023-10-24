import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/src/credentials/jsonLdContext/did_context.dart';
import 'package:dart_ssi/src/credentials/jsonLdContext/json_web_signature_2020_context.dart';
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
  } else if (url.toString() == jsonWebSignature2020ContextIri) {
    return RemoteDocument(document: jsonWebSignature2020Context);
  } else if (url.toString() == jsonWebSignature2020ContextIri2) {
    return RemoteDocument(document: jsonWebSignature2020Context);
  } else if (url.toString() == didContextIri) {
    return RemoteDocument(document: didContext);
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
  } else if (url.toString() == jsonWebSignature2020ContextIri) {
    return RemoteDocument(document: jsonWebSignature2020Context);
  } else if (url.toString() == jsonWebSignature2020ContextIri2) {
    return RemoteDocument(document: jsonWebSignature2020Context);
  } else if (url.toString() == didContextIri) {
    return RemoteDocument(document: didContext);
  } else {
    return await loadDocument(url, options);
  }
}
