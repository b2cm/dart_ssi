import 'dart:convert';

import 'package:uuid/uuid.dart';

import '../../credentials/credential_manifest.dart';
import '../../credentials/verifiable_credential.dart';
import '../../util/types.dart';
import '../../util/utils.dart';
import '../didcomm_jwm.dart';
import '../types.dart';

class ProposeCredential extends DidcommPlaintextMessage {
  String? goalCode;
  String? comment;
  PreviewCredential? credentialPreview;
  List<LdProofVcDetail>? detail;

  ProposeCredential(
      {String? id,
      this.goalCode,
      this.comment,
      this.credentialPreview,
      this.detail,
      super.replyUrl,
      super.replyTo,
      super.parentThreadId,
      super.threadId,
      super.from,
      List<String>? super.to,
      super.createdTime,
      super.expiresTime,
      super.pleaseAck,
      super.fromPrior,
      super.additionalHeaders,
      super.webRedirect,
      super.returnRoute,
      super.typ})
      : super(
            type: DidcommMessages.proposeCredential,
            id: id ?? Uuid().v4(),
            body: {}) {
    if (comment != null) body['comment'] = comment;
    if (goalCode != null) body['goal_code'] = goalCode;
    if (credentialPreview != null) {
      body['credential_preview'] = credentialPreview!.toJson();
    }
    if (detail != null) {
      attachments = [];
      for (var a in detail!) {
        attachments!.add(Attachment(
            data: AttachmentData(json: a.toJson()),
            id: Uuid().v4(),
            format: AttachmentFormat.ldProofVcDetail,
            mediaType: 'application/json'));
      }
    }
  }

  ProposeCredential.fromJson(super.jsonObject) : super.fromJson() {
    if (type != DidcommMessages.proposeCredential) {
      throw Exception('Unknown Message type or version');
    }
    goalCode = body['goal_code'];
    comment = body['comment'];
    if (body.containsKey('credential_preview')) {
      credentialPreview =
          PreviewCredential.fromJson(body['credential_preview']);
    }
    if (attachments != null && attachments!.isNotEmpty) {
      detail = [];
      for (var a in attachments!) {
        if (a.format != null && a.format == AttachmentFormat.ldProofVcDetail) {
          if (a.mediaType != null && a.mediaType == 'application/json') {
            a.data.resolveData();
            detail!.add(LdProofVcDetail.fromJson(a.data.json!));
          }
        } else if (a.format != null &&
            a.format == AttachmentFormat.credentialManifestAries) {
          throw UnimplementedError(
              'dif credential Manifest Attachment is not supported yet');
        } else if (a.format != null &&
            a.format == AttachmentFormat.indyCredentialFilter) {
          throw UnimplementedError('indy Attachment is not supported');
        } else {
          continue;
        }
      }
    }
  }
}

class OfferCredential extends DidcommPlaintextMessage {
  String? goalCode;
  String? comment;
  String? replacementId;
  PreviewCredential? credentialPreview;
  List<LdProofVcDetail>? detail;
  CredentialManifestAttachment? credentialManifest;
  VerifiablePresentation? fulfillment;

  OfferCredential(
      {String? id,
      this.replacementId,
      this.goalCode,
      this.comment,
      this.credentialPreview,
      this.detail,
      this.credentialManifest,
      this.fulfillment,
      super.replyUrl,
      super.replyTo,
      super.parentThreadId,
      super.threadId,
      super.from,
      List<String>? super.to,
      super.createdTime,
      super.expiresTime,
      super.pleaseAck,
      super.fromPrior,
      super.additionalHeaders,
      super.webRedirect,
      super.returnRoute,
      super.typ})
      : super(
            type: DidcommMessages.offerCredential,
            id: id ?? Uuid().v4(),
            body: {}) {
    if (comment != null) body['comment'] = comment;
    if (goalCode != null) body['goal_code'] = goalCode;
    if (replacementId != null) body['replacement_id'] = replacementId;
    if (credentialPreview != null) {
      body['credential_preview'] = credentialPreview!.toJson();
    }
    if (detail != null) {
      attachments = [];
      for (var a in detail!) {
        attachments!.add(Attachment(
            data: AttachmentData(json: a.toJson()),
            id: Uuid().v4(),
            format: AttachmentFormat.ldProofVcDetail,
            mediaType: 'application/json'));
      }
    }
    if (credentialManifest != null) {
      attachments ??= [];
      attachments!.add(Attachment(
          data: AttachmentData(json: credentialManifest!.toJson()),
          id: Uuid().v4(),
          format: AttachmentFormat.credentialManifest,
          mediaType: 'application/json'));
    }

    if (fulfillment != null) {
      attachments ??= [];
      attachments!.add(Attachment(
          data: AttachmentData(json: fulfillment!.toJson()),
          id: Uuid().v4(),
          format: AttachmentFormat.credentialFulfillment,
          mediaType: 'application/json'));
    }
  }

  OfferCredential.fromJson(super.jsonObject) : super.fromJson() {
    if (type != DidcommMessages.offerCredential) {
      throw Exception('Unknown Message type or version');
    }
    goalCode = body['goal_code'];
    comment = body['comment'];
    replacementId = body['replacement_id'];
    if (body.containsKey('credential_preview')) {
      credentialPreview =
          PreviewCredential.fromJson(body['credential_preview']);
    }
    if (attachments != null && attachments!.isNotEmpty) {
      detail = [];
      for (var a in attachments!) {
        if (a.format != null && a.format == AttachmentFormat.ldProofVcDetail) {
          if (a.mediaType != null && a.mediaType == 'application/json') {
            a.data.resolveData();
            detail!.add(LdProofVcDetail.fromJson(a.data.json!));
          }
        } else if (a.format != null &&
            a.format == AttachmentFormat.credentialManifestAries) {
          throw UnimplementedError(
              'dif credential Manifest Attachment as specified in Aries RFC 0511 is not supported yet');
        } else if (a.format != null &&
            a.format == AttachmentFormat.credentialManifest) {
          credentialManifest =
              CredentialManifestAttachment.fromJson(a.data.json);
        } else if (a.format != null &&
            a.format == AttachmentFormat.credentialFulfillment) {
          fulfillment = VerifiablePresentation.fromJson(a.data.json);
          if (fulfillment?.credentialFulfillment == null) {
            throw Exception(
                'the presentation used here must contain a credential fulfillment');
          }
        } else if (a.format != null &&
            a.format == AttachmentFormat.indyCredentialAbstract) {
          throw UnimplementedError('indy Attachment is not supported');
        } else {
          continue;
        }
      }
    }
  }
}

class RequestCredential extends DidcommPlaintextMessage {
  String? goalCode;
  String? comment;
  List<LdProofVcDetail>? detail;
  VerifiablePresentation? credentialApplication;

  RequestCredential(
      {String? id,
      this.goalCode,
      this.comment,
      this.detail,
      this.credentialApplication,
      super.replyUrl,
      super.replyTo,
      super.parentThreadId,
      super.threadId,
      super.from,
      List<String>? super.to,
      super.createdTime,
      super.expiresTime,
      super.pleaseAck,
      super.fromPrior,
      super.additionalHeaders,
      super.webRedirect,
      super.returnRoute,
      super.typ})
      : super(
            type: DidcommMessages.requestCredential,
            id: id ?? Uuid().v4(),
            body: {}) {
    if (comment != null) body['comment'] = comment;
    if (goalCode != null) body['goal_code'] = goalCode;
    if (detail != null) {
      attachments = [];
      for (var a in detail!) {
        attachments!.add(Attachment(
            data: AttachmentData(json: a.toJson()),
            id: Uuid().v4(),
            format: AttachmentFormat.ldProofVcDetail,
            mediaType: 'application/json'));
      }
    }
    if (credentialApplication != null) {
      attachments ??= [];
      attachments!.add(Attachment(
          data: AttachmentData(json: credentialApplication!.toJson()),
          id: Uuid().v4(),
          format: AttachmentFormat.credentialApplication,
          mediaType: 'application/json'));
    }
  }

  RequestCredential.fromJson(super.jsonObject) : super.fromJson() {
    if (type != DidcommMessages.requestCredential) {
      throw Exception('Unknown Message type or version');
    }
    goalCode = body['goal_code'];
    comment = body['comment'];
    if (attachments != null && attachments!.isNotEmpty) {
      detail = [];
      for (var a in attachments!) {
        if (a.format != null && a.format == AttachmentFormat.ldProofVcDetail) {
          if (a.mediaType != null && a.mediaType == 'application/json') {
            a.data.resolveData();
            detail!.add(LdProofVcDetail.fromJson(a.data.json!));
          }
        } else if (a.format != null &&
            a.format == 'dif/credential-manifest@v1.0') {
          throw UnimplementedError(
              'dif credential Manifest Attachment as described in Aries RFC 511 is not supported yet');
        } else if (a.format != null &&
            a.format == AttachmentFormat.credentialApplication) {
          credentialApplication = VerifiablePresentation.fromJson(a.data.json);
        } else if (a.format != null &&
            a.format == AttachmentFormat.indyCredentialRequest) {
          throw UnimplementedError('indy Attachment is not supported');
        } else {
          continue;
        }
      }
    }
  }
}

class IssueCredential extends DidcommPlaintextMessage {
  String? goalCode;
  String? replacementId;
  String? comment;
  List<VerifiableCredential>? credentials;
  VerifiablePresentation? credentialFulfillment;

  IssueCredential(
      {String? id,
      this.goalCode,
      this.comment,
      this.replacementId,
      this.credentials,
      this.credentialFulfillment,
      super.replyUrl,
      super.replyTo,
      super.parentThreadId,
      super.threadId,
      super.from,
      List<String>? super.to,
      super.createdTime,
      super.expiresTime,
      super.pleaseAck,
      super.fromPrior,
      super.additionalHeaders,
      super.webRedirect,
      super.returnRoute,
      super.typ})
      : super(
            type: DidcommMessages.issueCredential,
            id: id ?? Uuid().v4(),
            body: {}) {
    if (comment != null) body['comment'] = comment;
    if (goalCode != null) body['goal_code'] = goalCode;
    if (replacementId != null) body['replacement_id'] = replacementId;
    if (credentials != null) {
      attachments = [];
      for (var a in credentials!) {
        attachments!.add(Attachment(
            data: AttachmentData(json: a.toJson()),
            id: Uuid().v4(),
            format: AttachmentFormat.ldProofVc,
            mediaType: 'application/json'));
      }
    }
    if (credentialFulfillment != null) {
      attachments ??= [];
      attachments!.add(Attachment(
          data: AttachmentData(json: credentialFulfillment!.toJson()),
          id: Uuid().v4(),
          format: AttachmentFormat.credentialFulfillment,
          mediaType: 'application/json'));
    }
  }

  IssueCredential.fromJson(super.jsonObject) : super.fromJson() {
    if (type != DidcommMessages.issueCredential) {
      throw Exception('Unknown Message type or version');
    }
    goalCode = body['goal_code'];
    comment = body['comment'];
    replacementId = body['replacement_id'];
    if (attachments != null && attachments!.isNotEmpty) {
      credentials = [];
      for (var a in attachments!) {
        if (a.format != null && a.format == AttachmentFormat.ldProofVc) {
          if (a.mediaType != null && a.mediaType == 'application/json') {
            a.data.resolveData();
            credentials!.add(VerifiableCredential.fromJson(a.data.json!));
          }
        } else if (a.format != null &&
            a.format == AttachmentFormat.credentialFulfillment) {
          credentialFulfillment = VerifiablePresentation.fromJson(a.data.json);
        } else if (a.format != null &&
            a.format == AttachmentFormat.indyCredential) {
          throw UnimplementedError('indy Attachment is not supported');
        } else {
          throw Exception('Unknown Attachment Format');
        }
      }
    }
  }
}

class PreviewCredential extends DidcommPlaintextMessage {
  late List<PreviewCredentialAttribute> attributes;

  PreviewCredential(
      {String? id,
      required this.attributes,
      super.replyUrl,
      super.replyTo,
      super.parentThreadId,
      super.threadId,
      super.from,
      List<String>? super.to,
      super.createdTime,
      super.expiresTime,
      super.pleaseAck,
      super.fromPrior,
      super.additionalHeaders,
      super.webRedirect,
      super.returnRoute,
      super.typ})
      : super(
            id: id ?? Uuid().v4(),
            type: DidcommMessages.previewCredential,
            body: {'attributes': attributes});

  PreviewCredential.fromJson(super.jsonObject) : super.fromJson() {
    if (type ==
            'https://didcomm.org/issue-credential/3.0/credential-credential' ||
        type == DidcommMessages.previewCredential) {
      if (body.containsKey('attributes')) {
        List tmp = body['attributes'];
        attributes = [];
        for (var a in tmp) {
          attributes.add(PreviewCredentialAttribute.fromJson(a));
        }
      }
    }
  }
}

class PreviewCredentialAttribute implements JsonObject {
  late String name;
  String? mimeType;
  late String value;

  PreviewCredentialAttribute(
      {required this.name, required this.value, this.mimeType});

  PreviewCredentialAttribute.fromJson(dynamic jsonObject) {
    var previewAttribute = credentialToMap(jsonObject);
    if (previewAttribute.containsKey('name')) {
      name = previewAttribute['name'];
    } else {
      throw FormatException(
          'name property needed in Attribute for Credential Preview');
    }
    if (previewAttribute.containsKey('value')) {
      value = previewAttribute['value'];
    } else {
      throw FormatException(
          'value property needed in Attribute for Credential Preview');
    }
    mimeType = previewAttribute['mime-type'];
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['name'] = name;
    if (mimeType != null) jsonObject['mime-type'] = mimeType;
    jsonObject['value'] = value;
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

//******Json-Ld Attachment (RFC 0593) ********
class LdProofVcDetail implements JsonObject {
  late VerifiableCredential credential;
  late LdProofVcDetailOptions options;

  LdProofVcDetail({required this.credential, required this.options});

  LdProofVcDetail.fromJson(dynamic jsonObject) {
    var vcDetail = credentialToMap(jsonObject);
    if (vcDetail.containsKey('credential')) {
      credential = VerifiableCredential.fromJson(vcDetail['credential']);
    } else {
      throw FormatException('credential property is needed in LdProofVcDetail');
    }
    if (vcDetail.containsKey('options')) {
      options = LdProofVcDetailOptions.fromJson(vcDetail['options']);
    } else {
      throw FormatException('options property is needed in LdProofVcDetail');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['credential'] = credential.toJson();
    jsonObject['options'] = options.toJson();
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class LdProofVcDetailOptions implements JsonObject {
  late String proofType;
  String? proofPurpose;
  DateTime? created;
  String? challenge;
  String? domain;
  String? credentialStatusType;

  LdProofVcDetailOptions(
      {required this.proofType,
      this.proofPurpose,
      this.created,
      this.challenge,
      this.domain,
      this.credentialStatusType});

  LdProofVcDetailOptions.fromJson(dynamic jsonObject) {
    var options = credentialToMap(jsonObject);
    if (options.containsKey('proofType')) {
      proofType = options['proofType'];
    } else {
      throw FormatException('proofType is needed in Options Object');
    }
    proofPurpose = options['proofPurpose'];
    if (options.containsKey('created')) {
      created = DateTime.parse(options['created']);
    }
    challenge = options['challenge'];
    domain = options['domain'];
    if (options.containsKey('credentialStatus')) {
      Map<String, dynamic> tmp = options['credentialStatus'];
      if (tmp.containsKey('type')) {
        credentialStatusType = tmp['type'];
      } else {
        throw FormatException('type property is needed for credential Status');
      }
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['proofType'] = proofType;
    if (proofPurpose != null) jsonObject['proofPurpose'];
    if (created != null) jsonObject['created'] = created!.toIso8601String();
    if (challenge != null) jsonObject['challenge'] = challenge;
    if (domain != null) jsonObject['domain'] = domain;
    if (credentialStatusType != null) {
      jsonObject['credentialStatus'] = {'type': credentialStatusType};
    }
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class CredentialManifestAttachment implements JsonObject {
  late String challenge;
  late String domain;
  late CredentialManifest credentialManifest;

  CredentialManifestAttachment(
      {required this.challenge,
      required this.domain,
      required this.credentialManifest});

  CredentialManifestAttachment.fromJson(dynamic jsonObject) {
    var data = credentialToMap(jsonObject);
    Map? options = data['options'];
    if (options == null || options.isEmpty) {
      throw Exception('Options needed');
    }
    if (options.containsKey('challenge')) {
      challenge = options['challenge'];
    } else {
      throw Exception('Challenge property needed');
    }
    if (options.containsKey('domain')) {
      domain = options['domain'];
    } else {
      throw Exception('Domain Property needed');
    }

    if (data.containsKey('credential_manifest')) {
      credentialManifest =
          CredentialManifest.fromJson(data['credential_manifest']);
    } else {
      throw Exception('credential_manifest property needed');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    return {
      'challenge': challenge,
      'domain': domain,
      'credential_manifest': credentialManifest.toJson()
    };
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
