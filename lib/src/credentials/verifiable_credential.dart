import 'dart:convert';

import '../credential_operations.dart';
import '../types.dart';

class VerifiableCredential implements JsonObject {
  late List<String> context;
  String? id;
  late List<String> type;
  dynamic credentialSubject;
  dynamic issuer;
  late DateTime issuanceDate;
  LinkedDataProof? proof;
  DateTime? expirationDate;
  CredentialStatus? status;
  CredentialStatus? credentialSchema;

  VerifiableCredential(
      {required this.context,
      required this.type,
      required this.issuer,
      required this.credentialSubject,
      this.id,
      required this.issuanceDate,
      this.status,
      this.credentialSchema,
      this.expirationDate,
      this.proof});

  VerifiableCredential.fromJson(dynamic jsonObject) {
    var credential = credentialToMap(jsonObject);
    if (credential.containsKey('@context'))
      context = credential['@context'].cast<String>();
    else
      throw FormatException(
          '@context property is needed in verifiable credential');

    if (credential.containsKey('type'))
      type = credential['type'].cast<String>();
    else
      throw FormatException('type property is needed in verifiable credential');

    if (credential.containsKey('issuer'))
      issuer = credential['issuer'];
    else
      throw FormatException(
          'issuer property is needed in verifiable credential');

    if (credential.containsKey('credentialSubject')) {
      {
        credentialSubject = credential['credentialSubject'];
        if (!credentialSubject is Map<String, dynamic>)
          throw FormatException(
              'Credential subject property must be a Map (dart json Object)');
      }
    } else
      throw FormatException(
          'credential subject property is needed in verifiable credential');

    if (credential.containsKey('issuanceDate'))
      issuanceDate = DateTime.parse(credential['issuer']);
    else
      throw FormatException(
          'issuer property is needed in verifiable credential');

    id = credential['id'];

    if (credential.containsKey('expirationDate'))
      expirationDate = DateTime.parse(credential['expirationDate']);

    if (credential.containsKey(['credentialStatus']))
      status = CredentialStatus.fromJson(credential['credentialStatus']);

    if (credential.containsKey('proof'))
      proof = LinkedDataProof.fromJson(credential['proof']);

    if (credential.containsKey('credentialSchema'))
      credentialSchema =
          CredentialStatus.fromJson(credential['credentialSchema']);
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['@context'] = context;
    if (id != null) jsonObject['id'] = id;
    jsonObject['type'] = type;
    jsonObject['credentialSubject'] = credentialSubject;
    jsonObject['issuer'] = issuer;
    jsonObject['issuanceDate'] = issuanceDate.toIso8601String();
    if (proof != null) jsonObject['proof'] = proof!.toJson();
    if (status != null) jsonObject['credentialStatus'] = status!.toJson();
    if (credentialSchema != null)
      jsonObject['credentialSchema'] = credentialSchema!.toJson();

    return jsonObject;
  }

  String toString() {
    return jsonEncode(toJson());
  }
}

class LinkedDataProof implements JsonObject {
  late String type;
  late String proofPurpose;
  late String verificationMethod;
  late DateTime created;
  late String proofValue;
  String? domain;

  LinkedDataProof(
      {required this.type,
      required this.proofPurpose,
      required this.verificationMethod,
      required this.created,
      required this.proofValue,
      this.domain});

  LinkedDataProof.fromJson(dynamic jsonObject) {
    var proof = credentialToMap(jsonObject);
    if (proof.containsKey('type'))
      type = proof['type'];
    else
      throw FormatException('Type property is needed in proof object');

    if (proof.containsKey('proofPurpose'))
      proofPurpose = proof['proofPurpose'];
    else
      throw FormatException('proofPurpose property is needed in proof object');

    if (proof.containsKey('verificationMethod'))
      verificationMethod = proof['verificationMethod'];
    else
      throw FormatException('verification Method is needed in proof object');

    if (proof.containsKey('created'))
      created = DateTime.parse(proof['created']);
    else
      throw FormatException('created is needed in proof object');

    if (proof.containsKey('proofValue'))
      proofValue = proof['proofValue'];
    else
      throw FormatException('proof value is needed in proof object');

    domain = proof['domain'];
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['type'] = type;
    jsonObject['proofPurpose'] = proofPurpose;
    jsonObject['verificationMethod'] = verificationMethod;
    jsonObject['created'] = created.toIso8601String();
    jsonObject['proofValue'] = proofValue;
    if (domain != null) jsonObject['domain'] = domain;
    return jsonObject;
  }

  String toString() {
    return jsonEncode(toJson());
  }
}

class CredentialStatus implements JsonObject {
  late String id;
  late String type;

  CredentialStatus(this.id, this.type);

  CredentialStatus.fromJson(dynamic jsonObject) {
    var status = credentialToMap(jsonObject);
    if (status.containsKey('id'))
      id = status['id'];
    else
      throw FormatException('id property is needed in Credential Status');
    if (status.containsKey('type'))
      type = status['type'];
    else
      throw FormatException('tpe property is needed in credentialStatus');
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    jsonObject['type'] = type;
    return jsonObject;
  }

  String toString() {
    return jsonEncode(toJson());
  }
}
