import 'dart:convert';

import 'package:uuid/uuid.dart';

import '../../credentials/verifiable_credential.dart';
import '../../util/types.dart';
import '../../util/utils.dart';
import '../didcomm_jwm.dart';

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
      this.detail})
      : super(
            type: 'https://didcomm.org/issue-credential/3.0/propose-credential',
            id: id ?? Uuid().v4(),
            body: {}) {
    if (comment != null) body['comment'] = comment;
    if (goalCode != null) body['goal_code'] = goalCode;
    if (credentialPreview != null)
      body['credential_preview'] = credentialPreview!.toJson();
    if (detail != null) {
      attachments = [];
      for (var a in detail!) {
        attachments!.add(Attachment(
            data: AttachmentData(json: a.toJson()),
            id: Uuid().v4(),
            format: 'aries/ld-proof-vc-detail@v1.0',
            mediaType: 'application/json'));
      }
    }
  }

  ProposeCredential.fromJson(dynamic jsonObject) : super.fromJson(jsonObject) {
    if (type != 'https://didcomm.org/issue-credential/3.0/propose-credential')
      throw Exception('Unknown Message type or version');
    goalCode = body['goal_code'];
    comment = body['comment'];
    if (body.containsKey('credential_preview'))
      credentialPreview =
          PreviewCredential.fromJson(body['credential_preview']);
    if (attachments != null && attachments!.length > 0) {
      detail = [];
      for (var a in attachments!) {
        if (a.format != null && a.format == 'aries/ld-proof-vc-detail@v1.0') {
          if (a.mediaType != null && a.mediaType == 'application/json') {
            a.data.resolveData();
            detail!.add(LdProofVcDetail.fromJson(a.data.json!));
          }
        } else if (a.format != null &&
            a.format == 'dif/credential-manifest@v1.0') {
          throw UnimplementedError(
              'dif credential Manifest Attachment is not supported yet');
        } else if (a.format != null && a.format == 'hlindy/cred-filter@v2.0') {
          throw UnimplementedError('indy Attachment is not supported');
        } else
          throw Exception('Unknown Attachment Format');
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

  OfferCredential(
      {String? id,
      this.replacementId,
      this.goalCode,
      this.comment,
      this.credentialPreview,
      this.detail})
      : super(
            type: 'https://didcomm.org/issue-credential/3.0/offer-credential',
            id: id ?? Uuid().v4(),
            body: {}) {
    if (comment != null) body['comment'] = comment;
    if (goalCode != null) body['goal_code'] = goalCode;
    if (replacementId != null) body['replacement_id'] = replacementId;
    if (credentialPreview != null)
      body['credential_preview'] = credentialPreview!.toJson();
    if (detail != null) {
      attachments = [];
      for (var a in detail!) {
        attachments!.add(Attachment(
            data: AttachmentData(json: a.toJson()),
            id: Uuid().v4(),
            format: 'aries/ld-proof-vc-detail@v1.0',
            mediaType: 'application/json'));
      }
    }
  }

  OfferCredential.fromJson(dynamic jsonObject) : super.fromJson(jsonObject) {
    if (type != 'https://didcomm.org/issue-credential/3.0/offer-credential')
      throw Exception('Unknown Message type or version');
    goalCode = body['goal_code'];
    comment = body['comment'];
    replacementId = body['replacement_id'];
    if (body.containsKey('credential_preview'))
      credentialPreview =
          PreviewCredential.fromJson(body['credential_preview']);
    if (attachments != null && attachments!.length > 0) {
      detail = [];
      for (var a in attachments!) {
        if (a.format != null && a.format == 'aries/ld-proof-vc-detail@v1.0') {
          if (a.mediaType != null && a.mediaType == 'application/json') {
            a.data.resolveData();
            detail!.add(LdProofVcDetail.fromJson(a.data.json!));
          }
        } else if (a.format != null &&
            a.format == 'dif/credential-manifest@v1.0') {
          throw UnimplementedError(
              'dif credential Manifest Attachment is not supported yet');
        } else if (a.format != null &&
            a.format == 'hlindy/cred-abstract@v2.0') {
          throw UnimplementedError('indy Attachment is not supported');
        } else
          throw Exception('Unknown Attachment Format');
      }
    }
  }
}

class RequestCredential extends DidcommPlaintextMessage {
  String? goalCode;
  String? comment;
  List<LdProofVcDetail>? detail;

  RequestCredential({String? id, this.goalCode, this.comment, this.detail})
      : super(
            type: 'https://didcomm.org/issue-credential/3.0/request-credential',
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
            format: 'aries/ld-proof-vc-detail@v1.0',
            mediaType: 'application/json'));
      }
    }
  }

  RequestCredential.fromJson(dynamic jsonObject) : super.fromJson(jsonObject) {
    if (type != 'https://didcomm.org/issue-credential/3.0/request-credential')
      throw Exception('Unknown Message type or version');
    goalCode = body['goal_code'];
    comment = body['comment'];
    if (attachments != null && attachments!.length > 0) {
      detail = [];
      for (var a in attachments!) {
        if (a.format != null && a.format == 'aries/ld-proof-vc-detail@v1.0') {
          if (a.mediaType != null && a.mediaType == 'application/json') {
            a.data.resolveData();
            detail!.add(LdProofVcDetail.fromJson(a.data.json!));
          }
        } else if (a.format != null &&
            a.format == 'dif/credential-manifest@v1.0') {
          throw UnimplementedError(
              'dif credential Manifest Attachment is not supported yet');
        } else if (a.format != null && a.format == 'hlindy/cred-req@v2.0') {
          throw UnimplementedError('indy Attachment is not supported');
        } else
          throw Exception('Unknown Attachment Format');
      }
    }
  }
}

class IssueCredential extends DidcommPlaintextMessage {
  String? goalCode;
  String? replacementId;
  String? comment;
  List<VerifiableCredential>? credentials;

  IssueCredential(
      {String? id,
      this.goalCode,
      this.comment,
      this.replacementId,
      this.credentials})
      : super(
            type: 'https://didcomm.org/issue-credential/3.0/issue-credential',
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
            format: 'aries/ld-proof-vc@v1.0',
            mediaType: 'application/json'));
      }
    }
  }

  IssueCredential.fromJson(dynamic jsonObject) : super.fromJson(jsonObject) {
    if (type != 'https://didcomm.org/issue-credential/3.0/request-credential')
      throw Exception('Unknown Message type or version');
    goalCode = body['goal_code'];
    comment = body['comment'];
    replacementId = body['replacement_id'];
    if (attachments != null && attachments!.length > 0) {
      credentials = [];
      for (var a in attachments!) {
        if (a.format != null && a.format == 'aries/ld-proof-vc-detail@v1.0') {
          if (a.mediaType != null && a.mediaType == 'application/json') {
            a.data.resolveData();
            credentials!.add(VerifiableCredential.fromJson(a.data.json!));
          }
        } else if (a.format != null && a.format == 'hlindy/cred@v2.0') {
          throw UnimplementedError('indy Attachment is not supported');
        } else
          throw Exception('Unknown Attachment Format');
      }
    }
  }
}

class PreviewCredential extends DidcommPlaintextMessage {
  late List<PreviewCredentialAttribute> attributes;

  PreviewCredential({String? id, required this.attributes})
      : super(
            id: id ?? Uuid().v4(),
            type: 'https://didcomm.org/issue-credential/3.0/credential-preview',
            body: {'attributes': attributes});

  PreviewCredential.fromJson(dynamic jsonObject) : super.fromJson(jsonObject) {
    if (type ==
            'https://didcomm.org/issue-credential/3.0/credential-credential' ||
        type == 'https://didcomm.org/issue-credential/3.0/credential-preview') {
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
    if (previewAttribute.containsKey('name'))
      name = previewAttribute['name'];
    else
      throw FormatException(
          'name property needed in Attribute for Credential Preview');
    if (previewAttribute.containsKey(['value']))
      value = previewAttribute['value'];
    else
      throw FormatException(
          'value property needed in Attribute for Credential Preview');
    mimeType = previewAttribute['mime-type'];
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['name'] = name;
    if (mimeType != null) jsonObject['mime-type'] = mimeType;
    jsonObject['value'] = value;
    return jsonObject;
  }

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
    if (vcDetail.containsKey('credential'))
      credential = VerifiableCredential.fromJson(vcDetail['credential']);
    else
      throw FormatException('credential property is needed in LdProofVcDetail');
    if (vcDetail.containsKey('options'))
      options = LdProofVcDetailOptions.fromJson(vcDetail['options']);
    else
      throw FormatException('options property is needed in LdProofVcDetail');
  }

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
    if (options.containsKey('proofType'))
      proofType = options['proofType'];
    else
      throw FormatException('proofType is needed in Options Object');
    proofPurpose = options['proofPurpose'];
    if (options.containsKey('created'))
      created = DateTime.parse(options['created']);
    challenge = options['challenge'];
    domain = options['domain'];
    if (options.containsKey('credentialStatus')) {
      Map<String, dynamic> tmp = options['credentialStatus'];
      if (tmp.containsKey(['type']))
        credentialStatusType = tmp['type'];
      else
        throw FormatException('type property is needed for credential Status');
    }
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['proofType'] = proofType;
    if (proofPurpose != null) jsonObject['proofPurpose'];
    if (created != null) jsonObject['created'] = created!.toIso8601String();
    if (challenge != null) jsonObject['challenge'] = challenge;
    if (domain != null) jsonObject['domain'] = domain;
    if (credentialStatusType != null)
      jsonObject['credentialStatus'] = {'type': credentialStatusType};
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
