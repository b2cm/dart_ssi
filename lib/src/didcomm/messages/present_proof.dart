import 'dart:convert';

import 'package:flutter_ssi_wallet/src/types.dart';
import 'package:uuid/uuid.dart';

import '../../credential_operations.dart';
import '../../credentials/presentation_exchange.dart';
import '../didcomm_jwm.dart';

class ProposePresentation {
  late String type;
  late String id;
  String? goalCode;
  String? comment;
  late Attachment attachment;

  ProposePresentation(
      String version, PresentationDefinition presentationDefinition,
      {String? idValue, String? attachmentId, this.goalCode, this.comment}) {
    if (version == '3.0')
      type = 'https://didcomm.org/present-proof/3.0/propose-presentation';
    else
      throw Exception('Unsupported Version String');
    if (idValue == null)
      id = Uuid().v4();
    else
      id = idValue;

    attachment = Attachment(
        data: AttachmentData(json: presentationDefinition.toJson()),
        id: attachmentId,
        format: 'dif/presentation-exchange/definitions@v1.0',
        mediaType: 'application/json');
  }

  DidcommPlaintextMessage toV3Message() {
    Map<String, dynamic> body = {};
    if (goalCode != null) body['goal_code'] = goalCode;
    if (comment != null) body['comment'] = comment;
    return DidcommPlaintextMessage(
        id: id, type: type, body: body, attachments: [attachment]);
  }
}

class RequestPresentation {
  late String type;
  late String id;
  late bool willConfirm;
  String? goalCode;
  String? comment;
  late Attachment attachment;

  RequestPresentation(
      String version,
      PresentationDefinition presentationDefinition,
      PresentationRequestOptions options,
      {String? idValue,
      String? attachmentId,
      this.goalCode,
      this.comment,
      this.willConfirm = false}) {
    if (version == '3.0')
      type = 'https://didcomm.org/present-proof/3.0/request-presentation';
    else
      throw Exception('Unsupported Version String');
    if (idValue == null)
      id = Uuid().v4();
    else
      id = idValue;

    attachment = Attachment(
        data: AttachmentData(json: {
          'options:': options.toJson(),
          'presentation_definition': presentationDefinition.toJson()
        }),
        id: attachmentId,
        format: 'dif/presentation-exchange/definitions@v1.0',
        mediaType: 'application/json');
  }

  DidcommPlaintextMessage toV3Message() {
    Map<String, dynamic> body = {};
    if (goalCode != null) body['goal_code'] = goalCode;
    if (comment != null) body['comment'] = comment;
    body['will_confirm'] = willConfirm;
    return DidcommPlaintextMessage(
        id: id, type: type, body: body, attachments: [attachment]);
  }
}

class Presentation {
  late String type;
  late String id;
  String? goalCode;
  String? comment;
  late Attachment attachment;

  Presentation(String version, PresentationDefinition presentationDefinition,
      {String? idValue, String? attachmentId, this.goalCode, this.comment}) {
    if (version == '3.0')
      type = 'https://didcomm.org/present-proof/3.0/presentation';
    else
      throw Exception('Unsupported Version String');
    if (idValue == null)
      id = Uuid().v4();
    else
      id = idValue;

    attachment = Attachment(
        data: AttachmentData(json: presentationDefinition.toJson()),
        id: attachmentId,
        format: 'dif/presentation-exchange/submission@v1.0',
        mediaType: 'application/json');
  }

  DidcommPlaintextMessage toV3Message() {
    Map<String, dynamic> body = {};
    if (goalCode != null) body['goal_code'] = goalCode;
    if (comment != null) body['comment'] = comment;
    return DidcommPlaintextMessage(
        id: id, type: type, body: body, attachments: [attachment]);
  }
}

class PresentationRequestOptions implements JsonObject {
  late String domain;
  late String challenge;

  PresentationRequestOptions(this.domain, {String? challenge}) {
    if (challenge == null)
      this.challenge = Uuid().v4();
    else
      this.challenge = challenge;
  }

  PresentationRequestOptions.fromJson(dynamic jsonObject) {
    var options = credentialToMap(jsonObject);
    if (options.containsKey('domain'))
      domain = options['domain'];
    else
      throw FormatException('Options Object us contain domain property');
    if (options.containsKey('challenge'))
      challenge = options['challenge'];
    else
      throw FormatException('Options Object must contain challenge property');
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['domain'] = domain;
    jsonObject['challenge'] = challenge;
    return jsonObject;
  }

  String toString() {
    return jsonEncode(toJson());
  }
}
