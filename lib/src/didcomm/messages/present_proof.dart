import 'dart:convert';

import 'package:uuid/uuid.dart';

import '../../credentials/presentation_exchange.dart';
import '../../credentials/verifiable_credential.dart';
import '../../util/types.dart';
import '../../util/utils.dart';
import '../didcomm_jwm.dart';
import '../types.dart';

class ProposePresentation extends DidcommPlaintextMessage {
  String? goalCode;
  String? comment;
  late List<PresentationDefinition> presentationDefinition;

  ProposePresentation(
      {String? id,
      required this.presentationDefinition,
      this.goalCode,
      this.comment,
      String? replyUrl,
      List<String>? replyTo,
      String? parentThreadId,
      String? threadId,
      String? from,
      List<String>? to,
      DateTime? createdTime,
      DateTime? expiresTime,
      bool pleaseAck = false,
      FromPriorJWT? fromPrior,
      Map<String, dynamic>? additionalHeaders,
      WebRedirect? webRedirect,
      DidcommMessageTyp? typ})
      : super(
            id: id ?? Uuid().v4(),
            type: DidcommMessages.proposePresentation.value,
            body: {},
            replyUrl: replyUrl,
            replyTo: replyTo,
            threadId: threadId,
            parentThreadId: parentThreadId,
            from: from,
            to: to,
            createdTime: createdTime,
            expiresTime: expiresTime,
            pleaseAck: pleaseAck,
            fromPrior: fromPrior,
            additionalHeaders: additionalHeaders,
            webRedirect: webRedirect,
            typ: typ) {
    if (goalCode != null) body['goal_code'] = goalCode;
    if (comment != null) body['comment'] = comment;
    attachments = [];
    for (var d in presentationDefinition) {
      var attachment = Attachment(
          data: AttachmentData(json: d.toJson()),
          id: Uuid().v4(),
          format: AttachmentFormat.presentationDefinition.value,
          mediaType: 'application/json');
      attachments!.add(attachment);
    }
  }

  ProposePresentation.fromJson(dynamic jsonObject)
      : super.fromJson(jsonObject) {
    if (type != DidcommMessages.proposePresentation.value)
      throw Exception('Unsupported type or version');
    goalCode = body['goal_code'];
    comment = body['comment'];

    if (attachments != null && attachments!.length > 0) {
      presentationDefinition = [];

      for (var a in attachments!) {
        if (a.format == AttachmentFormat.presentationDefinition.value) {
          a.data.resolveData();
          presentationDefinition
              .add(PresentationDefinition.fromJson(a.data.json));
        } else if (a.format == AttachmentFormat.indyProofRequest.value) {
          throw UnimplementedError('Indy proof request is not supported');
        } else
          throw Exception('Unknown type');
      }
    }
  }
}

class RequestPresentation extends DidcommPlaintextMessage {
  late bool willConfirm;
  String? goalCode;
  String? comment;
  late List<PresentationDefinitionWithOptions> presentationDefinition;

  RequestPresentation(
      {String? id,
      required this.presentationDefinition,
      this.willConfirm = false,
      this.goalCode,
      this.comment,
      String? replyUrl,
      List<String>? replyTo,
      String? parentThreadId,
      String? threadId,
      String? from,
      List<String>? to,
      DateTime? createdTime,
      DateTime? expiresTime,
      bool pleaseAck = false,
      FromPriorJWT? fromPrior,
      Map<String, dynamic>? additionalHeaders,
      WebRedirect? webRedirect,
      DidcommMessageTyp? typ})
      : super(
            id: id ?? Uuid().v4(),
            type: DidcommMessages.requestPresentation.value,
            body: {},
            replyUrl: replyUrl,
            replyTo: replyTo,
            threadId: threadId,
            parentThreadId: parentThreadId,
            from: from,
            to: to,
            createdTime: createdTime,
            expiresTime: expiresTime,
            pleaseAck: pleaseAck,
            fromPrior: fromPrior,
            additionalHeaders: additionalHeaders,
            webRedirect: webRedirect,
            typ: typ) {
    if (goalCode != null) body['goal_code'] = goalCode;
    if (comment != null) body['comment'] = comment;
    body['will_confirm'] = willConfirm;
    attachments = [];
    for (var d in presentationDefinition) {
      var attachment = Attachment(
          data: AttachmentData(json: d.toJson()),
          id: Uuid().v4(),
          format: AttachmentFormat.presentationDefinition.value,
          mediaType: 'application/json');
      attachments!.add(attachment);
    }
  }

  RequestPresentation.fromJson(dynamic jsonObject)
      : super.fromJson(jsonObject) {
    if (type != DidcommMessages.requestPresentation.value)
      throw Exception('Unsupported type or version');
    goalCode = body['goal_code'];
    comment = body['comment'];
    willConfirm = body['will_confirm'];

    if (attachments != null && attachments!.length > 0) {
      presentationDefinition = [];

      for (var a in attachments!) {
        if (a.format == AttachmentFormat.presentationDefinition.value) {
          a.data.resolveData();
          presentationDefinition
              .add(PresentationDefinitionWithOptions.fromJson(a.data.json!));
        } else if (a.format == AttachmentFormat.indyProofRequest.value) {
          throw UnimplementedError('Indy proof request is not supported');
        } else
          throw Exception('Unknown type');
      }
    }
  }
}

class Presentation extends DidcommPlaintextMessage {
  String? goalCode;
  String? comment;
  late List<VerifiablePresentation> verifiablePresentation;

  Presentation(
      {String? id,
      required this.verifiablePresentation,
      this.goalCode,
      this.comment,
      String? replyUrl,
      List<String>? replyTo,
      String? parentThreadId,
      String? threadId,
      String? from,
      List<String>? to,
      DateTime? createdTime,
      DateTime? expiresTime,
      bool pleaseAck = false,
      FromPriorJWT? fromPrior,
      Map<String, dynamic>? additionalHeaders,
      WebRedirect? webRedirect,
      DidcommMessageTyp? typ})
      : super(
            id: id ?? Uuid().v4(),
            type: DidcommMessages.presentation.value,
            body: {},
            replyUrl: replyUrl,
            replyTo: replyTo,
            threadId: threadId,
            parentThreadId: parentThreadId,
            from: from,
            to: to,
            createdTime: createdTime,
            expiresTime: expiresTime,
            pleaseAck: pleaseAck,
            fromPrior: fromPrior,
            additionalHeaders: additionalHeaders,
            webRedirect: webRedirect,
            typ: typ) {
    if (goalCode != null) body['goal_code'] = goalCode;
    if (comment != null) body['comment'] = comment;
    attachments = [];
    for (var d in verifiablePresentation) {
      if (d.presentationSubmission == null)
        throw Exception(
            'The verifiable Presentation used here must contain a presentation submission');
      var attachment = Attachment(
          data: AttachmentData(json: d.toJson()),
          id: Uuid().v4(),
          format: AttachmentFormat.presentationSubmission.value,
          mediaType: 'application/json');
      attachments!.add(attachment);
    }
  }

  Presentation.fromJson(dynamic jsonObject) : super.fromJson(jsonObject) {
    if (type != DidcommMessages.presentation.value)
      throw Exception('Unsupported type or version');
    goalCode = body['goal_code'];
    comment = body['comment'];

    if (attachments != null && attachments!.length > 0) {
      verifiablePresentation = [];

      for (var a in attachments!) {
        if (a.format == AttachmentFormat.presentationSubmission.value) {
          a.data.resolveData();
          var tmp = VerifiablePresentation.fromJson(a.data.json);
          if (tmp.presentationSubmission == null)
            throw Exception(
                'The verifiable Presentation used here must contain a presentation submission');
          verifiablePresentation.add(tmp);
        } else if (a.format == AttachmentFormat.indyProof.value) {
          throw UnimplementedError('Indy proof request is not supported');
        } else
          throw Exception('Unknown type');
      }
    }
  }
}

class PresentationDefinitionWithOptions implements JsonObject {
  late String domain;
  late String challenge;
  late PresentationDefinition presentationDefinition;

  PresentationDefinitionWithOptions(
      {required this.domain,
      String? challenge,
      required this.presentationDefinition}) {
    if (challenge == null)
      this.challenge = Uuid().v4();
    else
      this.challenge = challenge;
  }

  PresentationDefinitionWithOptions.fromJson(dynamic jsonObject) {
    var object = credentialToMap(jsonObject);
    if (object.containsKey('options')) {
      Map<String, dynamic> options = object['options'];

      if (options.containsKey('domain'))
        domain = options['domain'];
      else
        throw FormatException('Options Object us contain domain property');
      if (options.containsKey('challenge'))
        challenge = options['challenge'];
      else
        throw FormatException('Options Object must contain challenge property');
    } else
      throw FormatException('options object needed');
    if (object.containsKey('presentation_definition'))
      presentationDefinition =
          PresentationDefinition.fromJson(object['presentation_definition']);
    else
      throw Exception('presentation_definition needed');
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    Map<String, dynamic> options = {};
    options['domain'] = domain;
    options['challenge'] = challenge;
    jsonObject['options'] = options;
    jsonObject['presentation_definition'] = presentationDefinition.toJson();
    return jsonObject;
  }

  String toString() {
    return jsonEncode(toJson());
  }
}
