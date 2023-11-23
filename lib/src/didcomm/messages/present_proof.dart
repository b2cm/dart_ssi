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
  List<PresentationDefinition>? presentationDefinition;

  ProposePresentation(
      {String? id,
      this.presentationDefinition,
      this.goalCode,
      this.comment,
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
            type: DidcommMessages.proposePresentation,
            body: {}) {
    if (goalCode != null) body['goal_code'] = goalCode;
    if (comment != null) body['comment'] = comment;
    attachments = [];
    if (presentationDefinition != null) {
      for (var d in presentationDefinition!) {
        var attachment = Attachment(
            data: AttachmentData(json: d.toJson()),
            id: Uuid().v4(),
            format: AttachmentFormat.presentationDefinition,
            mediaType: 'application/json');
        attachments!.add(attachment);
      }
    }
  }

  ProposePresentation.fromJson(super.jsonObject)
      : super.fromJson() {
    if (type != DidcommMessages.proposePresentation) {
      throw Exception('Unsupported type or version');
    }
    goalCode = body['goal_code'];
    comment = body['comment'];

    if (attachments != null && attachments!.isNotEmpty) {
      presentationDefinition = [];

      for (var a in attachments!) {
        if (a.format == AttachmentFormat.presentationDefinition) {
          a.data.resolveData();
          presentationDefinition!
              .add(PresentationDefinition.fromJson(a.data.json));
        } else if (a.format == AttachmentFormat.indyProofRequest) {
          throw UnimplementedError('Indy proof request is not supported');
        } else {
          throw Exception('Unknown type');
        }
      }
    }
  }
}

class RequestPresentation extends DidcommPlaintextMessage {
  bool? willConfirm;
  String? goalCode;
  String? comment;
  late List<PresentationDefinitionWithOptions> presentationDefinition;

  RequestPresentation(
      {String? id,
      required this.presentationDefinition,
      this.willConfirm = false,
      this.goalCode,
      this.comment,
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
            type: DidcommMessages.requestPresentation,
            body: {}) {
    if (goalCode != null) body['goal_code'] = goalCode;
    if (comment != null) body['comment'] = comment;
    body['will_confirm'] = willConfirm;
    attachments = [];
    for (var d in presentationDefinition) {
      var attachment = Attachment(
          data: AttachmentData(json: d.toJson()),
          id: Uuid().v4(),
          format: AttachmentFormat.presentationDefinition2,
          mediaType: 'application/json');
      attachments!.add(attachment);
    }
  }

  RequestPresentation.fromJson(super.jsonObject)
      : super.fromJson() {
    if (type != DidcommMessages.requestPresentation) {
      throw Exception('Unsupported type or version');
    }
    goalCode = body['goal_code'];
    comment = body['comment'];
    if (body['will_confirm'] != null) {
      willConfirm = body['will_confirm'];
    }

    if (attachments != null && attachments!.isNotEmpty) {
      presentationDefinition = [];

      for (var a in attachments!) {
        if (a.format == AttachmentFormat.presentationDefinition ||
            a.format == AttachmentFormat.presentationDefinition2) {
          a.data.resolveData();
          presentationDefinition
              .add(PresentationDefinitionWithOptions.fromJson(a.data.json!));
        } else if (a.format == AttachmentFormat.indyProofRequest) {
          throw UnimplementedError('Indy proof request is not supported');
        } else {
          //throw Exception('Unknown type');
        }
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
            type: DidcommMessages.presentation,
            body: {}) {
    if (goalCode != null) body['goal_code'] = goalCode;
    if (comment != null) body['comment'] = comment;
    attachments = [];
    for (var d in verifiablePresentation) {
      if (d.presentationSubmission == null) {
        throw Exception(
            'The verifiable Presentation used here must contain a presentation submission');
      }
      var attachment = Attachment(
          data: AttachmentData(json: d.toJson()),
          id: Uuid().v4(),
          format: AttachmentFormat.presentationSubmission2,
          mediaType: 'application/json');
      attachments!.add(attachment);
    }
  }

  Presentation.fromJson(super.jsonObject) : super.fromJson() {
    if (type != DidcommMessages.presentation) {
      throw Exception('Unsupported type or version');
    }
    goalCode = body['goal_code'];
    comment = body['comment'];

    if (attachments != null && attachments!.isNotEmpty) {
      verifiablePresentation = [];

      for (var a in attachments!) {
        if (a.format == AttachmentFormat.presentationSubmission ||
            a.format == AttachmentFormat.presentationSubmission2) {
          a.data.resolveData();
          var tmp = VerifiablePresentation.fromJson(a.data.json);
          if (tmp.presentationSubmission == null) {
            throw Exception(
                'The verifiable Presentation used here must contain a presentation submission');
          }
          verifiablePresentation.add(tmp);
        } else if (a.format == AttachmentFormat.indyProof) {
          throw UnimplementedError('Indy proof request is not supported');
        } else {
          //throw Exception('Unknown type: ${a.format}');
        }
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
    if (challenge == null) {
      this.challenge = Uuid().v4();
    } else {
      this.challenge = challenge;
    }
  }

  PresentationDefinitionWithOptions.fromJson(dynamic jsonObject) {
    var object = credentialToMap(jsonObject);
    if (object.containsKey('options')) {
      Map<String, dynamic> options = object['options'];

      if (options.containsKey('domain')) {
        domain = options['domain'];
      } else {
        throw FormatException('Options Object us contain domain property');
      }
      if (options.containsKey('challenge')) {
        challenge = options['challenge'];
      } else {
        throw FormatException('Options Object must contain challenge property');
      }
    } else {
      throw FormatException('options object needed');
    }
    if (object.containsKey('presentation_definition')) {
      presentationDefinition =
          PresentationDefinition.fromJson(object['presentation_definition']);
    } else {
      throw Exception('presentation_definition needed');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    Map<String, dynamic> options = {};
    options['domain'] = domain;
    options['challenge'] = challenge;
    jsonObject['options'] = options;
    jsonObject['presentation_definition'] = presentationDefinition.toJson();
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
