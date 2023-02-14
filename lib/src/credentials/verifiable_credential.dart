import 'dart:convert';

import 'package:dart_ssi/src/credentials/revocation_list_2020.dart';

import '../util/types.dart';
import '../util/utils.dart';
import 'credential_manifest.dart';
import 'presentation_exchange.dart';

class VerifiableCredential implements JsonObject {
  late List<dynamic> context;
  String? id;
  late List<String> type;
  dynamic credentialSubject;
  dynamic issuer;
  late DateTime issuanceDate;
  LinkedDataProof? proof;
  DateTime? expirationDate;
  CredentialStatus? status;
  CredentialStatus? credentialSchema;
  Map<String, dynamic>? _originalDoc;

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
    if (credential.containsKey('@context')) {
      context = credential['@context'];
    } else {
      throw FormatException(
          '@context property is needed in verifiable credential');
    }

    if (credential.containsKey('type')) {
      type = credential['type'].cast<String>();
    } else {
      throw FormatException('type property is needed in verifiable credential');
    }

    if (credential.containsKey('issuer')) {
      issuer = credential['issuer'];
    } else {
      throw FormatException(
          'issuer property is needed in verifiable credential');
    }

    if (credential.containsKey('credentialSubject')) {
      {
        credentialSubject = credential['credentialSubject'];
        if (credentialSubject is! Map<String, dynamic>) {
          if (credentialSubject is! List) {
            throw FormatException(
                'Credential subject property must be a Map or List (dart json Object)');
          }
        }
      }
    } else {
      throw FormatException(
          'credential subject property is needed in verifiable credential');
    }

    if (credential.containsKey('issuanceDate')) {
      issuanceDate = DateTime.parse(credential['issuanceDate']);
    } else {
      throw FormatException(
          'issuanceDate property is needed in verifiable credential');
    }

    id = credential['id'];

    if (credential.containsKey('expirationDate')) {
      expirationDate = DateTime.parse(credential['expirationDate']);
    }

    if (credential.containsKey(['credentialStatus'])) {
      status = CredentialStatus.fromJson(credential['credentialStatus']);
    }

    if (credential.containsKey('proof')) {
      proof = LinkedDataProof.fromJson(credential['proof']);
    }

    if (credential.containsKey('credentialSchema')) {
      credentialSchema =
          CredentialStatus.fromJson(credential['credentialSchema']);
    }

    _originalDoc = credential;
  }

  @override
  Map<String, dynamic> toJson() {
    if (_originalDoc != null) return _originalDoc!;
    Map<String, dynamic> jsonObject = {};
    jsonObject['@context'] = context;
    if (id != null) jsonObject['id'] = id;
    jsonObject['type'] = type;
    jsonObject['credentialSubject'] = credentialSubject;
    jsonObject['issuer'] = issuer;
    jsonObject['issuanceDate'] = issuanceDate.toIso8601String();
    if (proof != null) jsonObject['proof'] = proof!.toJson();
    if (status != null) jsonObject['credentialStatus'] = status!.toJson();
    if (credentialSchema != null) {
      jsonObject['credentialSchema'] = credentialSchema!.toJson();
    }

    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }

  bool isOfSameType(VerifiableCredential other) {
    if (credentialSchema != null && other.credentialSchema != null) {
      return credentialSchema!.type == other.credentialSchema!.type &&
          credentialSchema!.id == other.credentialSchema!.id;
    } else {
      for (String typeValue in type) {
        if (!other.type.contains(typeValue)) return false;
      }
      return true;
    }
  }

  bool isSelfIssued() {
    if (issuer is String && credentialSubject is String) {
      return issuer == credentialSubject;
    } else if (issuer is String && credentialSubject is Map) {
      return issuer == credentialSubject['id'];
    } else if (issuer is Map && credentialSubject is String) {
      return issuer['id'] == credentialSubject;
    } else if (issuer is Map && credentialSubject is Map) {
      return issuer['id'] == credentialSubject['id'];
    } else {
      return false;
    }
  }
}

class LinkedDataProof implements JsonObject {
  late String type;
  late String proofPurpose;
  late String verificationMethod;
  late DateTime created;
  String? proofValue;
  String? challenge;
  String? jws;
  String? domain;
  Map<String, dynamic>? _originalDoc;

  LinkedDataProof(
      {required this.type,
      required this.proofPurpose,
      required this.verificationMethod,
      required this.created,
      this.proofValue,
      this.challenge,
      this.jws,
      this.domain});

  LinkedDataProof.fromJson(dynamic jsonObject) {
    var proof = credentialToMap(jsonObject);
    if (proof.containsKey('type')) {
      type = proof['type'];
    } else {
      throw FormatException('Type property is needed in proof object');
    }

    if (proof.containsKey('proofPurpose')) {
      proofPurpose = proof['proofPurpose'];
    } else {
      throw FormatException('proofPurpose property is needed in proof object');
    }

    if (proof.containsKey('verificationMethod')) {
      verificationMethod = proof['verificationMethod'];
    } else {
      throw FormatException('verification Method is needed in proof object');
    }

    if (proof.containsKey('created')) {
      created = DateTime.parse(proof['created']);
    } else {
      throw FormatException('created is needed in proof object');
    }

    proofValue = proof['proofValue'];
    jws = proof['jws'];
    if (jws == null && proofValue == null) {
      throw FormatException('one of proofValue or jws must be present');
    }

    domain = proof['domain'];
    challenge = proof['challenge'];

    _originalDoc = proof;
  }

  @override
  Map<String, dynamic> toJson() {
    if (_originalDoc != null) return _originalDoc!;

    Map<String, dynamic> jsonObject = {};
    jsonObject['type'] = type;
    jsonObject['proofPurpose'] = proofPurpose;
    jsonObject['verificationMethod'] = verificationMethod;
    jsonObject['created'] = created.toIso8601String();
    if (domain != null) jsonObject['domain'] = domain;
    if (challenge != null) jsonObject['challenge'] = challenge;
    if (proofValue != null) jsonObject['proofValue'] = proofValue;
    if (jws != null) jsonObject['jws'] = jws;
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class CredentialStatus implements JsonObject {
  late String id;
  late String type;
  Map<String, dynamic>? _originalDoc;

  CredentialStatus(this.id, this.type, [this._originalDoc]);

  factory CredentialStatus.fromJson(dynamic jsonObject) {
    var status = credentialToMap(jsonObject);
    String id;
    if (status.containsKey('id')) {
      id = status['id'];
    } else {
      throw FormatException('id property is needed in Credential Status');
    }
    String type;
    if (status.containsKey('type')) {
      type = status['type'];
    } else {
      throw FormatException('type property is needed in credentialStatus');
    }

    if (type == 'RevocationList2020Status') {
      return RevocationList2020Status.fromJson(jsonObject);
    } else if (type == 'StatusList2021Entry') {
      return StatusList2021Entry.fromJson(jsonObject);
    } else {
      return CredentialStatus(id, type, status);
    }
  }

  @override
  Map<String, dynamic> toJson() {
    if (_originalDoc != null) return _originalDoc!;

    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    jsonObject['type'] = type;
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

//****** Presentation ******
class VerifiablePresentation implements JsonObject {
  late List<String> context;
  String? id;
  late List<String> type;
  late List<VerifiableCredential> verifiableCredential;
  String? holder;
  List<LinkedDataProof>? proof;
  PresentationSubmission? presentationSubmission;
  CredentialFulfillment? credentialFulfillment;
  CredentialApplication? credentialApplication;
  Map<String, dynamic>? _originalDoc;

  VerifiablePresentation(
      {required this.context,
      required this.type,
      required this.verifiableCredential,
      this.id,
      this.holder,
      this.proof,
      this.presentationSubmission,
      this.credentialFulfillment,
      this.credentialApplication});

  VerifiablePresentation.fromJson(dynamic jsonObject) {
    var presentation = credentialToMap(jsonObject);
    if (presentation.containsKey('@context')) {
      context = presentation['@context'].cast<String>();
    } else {
      throw FormatException(
          'context property is needed in verifiable presentation');
    }
    if (presentation.containsKey('type')) {
      type = presentation['type'].cast<String>();
    } else {
      throw FormatException(
          'type property is needed in verifiable presentation');
    }
    if (presentation.containsKey('verifiableCredential')) {
      verifiableCredential = [];
      List tmp = presentation['verifiableCredential'];
      for (var c in tmp) {
        verifiableCredential.add(VerifiableCredential.fromJson(c));
      }
    } else {
      throw FormatException(
          'verifiable credential property is needed in verifiable presentation');
    }
    id = presentation['id'];
    holder = presentation['holder'];
    if (presentation.containsKey('proof')) {
      proof = [];
      List tmp = presentation['proof'];
      for (var c in tmp) {
        proof!.add(LinkedDataProof.fromJson(c));
      }
    }

    if (presentation.containsKey('presentation_submission')) {
      var tmp = presentation['presentation_submission'];
      presentationSubmission = PresentationSubmission.fromJson(tmp);
    }

    if (presentation.containsKey('credential_fulfillment')) {
      credentialFulfillment = CredentialFulfillment.fromJson(
          presentation['credential_fulfillment']);
    }

    if (presentation.containsKey('credential_application')) {
      credentialApplication = CredentialApplication.fromJson(
          presentation['credential_application']);
    }

    _originalDoc = presentation;
  }

  @override
  Map<String, dynamic> toJson() {
    if (_originalDoc != null) return _originalDoc!;
    Map<String, dynamic> jsonObject = {};
    jsonObject['@context'] = context;
    jsonObject['type'] = type;
    List tmp = [];
    for (var c in verifiableCredential) {
      tmp.add(c.toJson());
    }
    jsonObject['verifiableCredential'] = tmp;
    if (id != null) jsonObject['id'] = id;
    if (holder != null) jsonObject['holder'] = holder;
    if (presentationSubmission != null) {
      jsonObject['presentation_submission'] = presentationSubmission!.toJson();
    }
    if (credentialFulfillment != null) {
      jsonObject['credential_fulfillment'] = credentialFulfillment!.toJson();
    }
    if (credentialApplication != null) {
      jsonObject['credential_application'] = credentialApplication!.toJson();
    }
    if (proof != null) {
      tmp = [];
      for (var p in proof!) {
        tmp.add(p.toJson());
      }
      jsonObject['proof'] = tmp;
    }
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
