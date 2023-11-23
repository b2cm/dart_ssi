import 'dart:convert';

import 'package:uuid/uuid.dart';

import '../../util/utils.dart';
import '../didcomm_jwm.dart';
import '../types.dart';

class EmptyMessage extends DidcommPlaintextMessage {
  EmptyMessage(
      {String? id,
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
      super.typ,
      super.webRedirect,
      super.returnRoute,
      super.ack,
      super.attachments})
      : super(
            id: id ?? Uuid().v4(),
            type: DidcommMessages.emptyMessage,
            body: {});

  EmptyMessage.fromJson(super.jsonObject) : super.fromJson() {
    if (type != DidcommMessages.emptyMessage) {
      throw Exception('Wrong message type');
    }
    if (body.isNotEmpty) throw Exception('this message is not empty');
  }
}

class ProblemReport extends DidcommPlaintextMessage {
  late String code;
  String? comment;
  List<String>? args;
  String? escalateTo;

  ProblemReport({
    String? id,
    required String super.parentThreadId,
    super.ack,
    required this.code,
    this.comment,
    this.args,
    this.escalateTo,
    super.replyUrl,
    super.replyTo,
    super.threadId,
    super.from,
    List<String>? super.to,
    super.createdTime,
    super.expiresTime,
    super.pleaseAck,
    super.fromPrior,
    super.additionalHeaders,
    super.typ,
    super.webRedirect,
    super.returnRoute,
  }) : super(
            id: id ?? Uuid().v4(),
            type: DidcommMessages.problemReport,
            body: {}) {
    body['code'] = code;
    if (comment != null) body['comment'] = comment;
    if (args != null) body['args'] = args;
    if (escalateTo != null) body['escalated_to'] = escalateTo;
  }

  ProblemReport.fromJson(super.jsonObject) : super.fromJson() {
    if (![
      DidcommMessages.problemReport,
      DidcommMessages.issueCredentialProblem,
      DidcommMessages.requestPresentationProblem
    ].contains(type)) {
      throw Exception('Wrong message type');
    }
    if (body.containsKey('code')) {
      code = body['code'];
    } else {
      throw FormatException('code property is needed in Problem Report');
    }
    comment = body['comment'];
    args = body['args'];
    escalateTo = body['escalate_to'];
  }

  /// Replaces placeholders in comment with args
  String interpolateComment() {
    String interpolatedComment = '';
    if (comment != null) {
      interpolatedComment = comment!;
      var index = interpolatedComment.indexOf('{');
      while (index != -1) {
        var index2 = interpolatedComment.indexOf('}', index);
        var argPos = interpolatedComment.substring(index + 1, index2);
        String replacement = '?';
        try {
          replacement = args![int.parse(argPos) - 1];
        } catch (e) {
          throw Exception('cant interpolate comment');
        }
        interpolatedComment =
            interpolatedComment.replaceRange(index, index2 + 1, replacement);
        index = interpolatedComment.indexOf('{');
      }
    }
    return interpolatedComment;
  }
}

class OutOfBandMessage extends DidcommPlaintextMessage {
  String? goalCode;
  String? goal;
  List<DidcommProfiles>? accept;

  OutOfBandMessage(
      {String? id,
      required String super.from,
      this.goalCode,
      this.goal,
      this.accept = const [DidcommProfiles.v2],
      super.attachments,
      super.replyUrl,
      super.replyTo,
      super.parentThreadId,
      super.threadId,
      List<String>? super.to,
      super.createdTime,
      super.expiresTime,
      super.pleaseAck,
      super.fromPrior,
      super.additionalHeaders,
      DidcommMessageTyp? typ,
      super.webRedirect,
      super.returnRoute})
      : super(
            id: id ?? Uuid().v4(),
            type: DidcommMessages.invitation,
            body: {},
            typ: DidcommMessageTyp.plain) {
    if (goal != null) body['goal'] = goal;
    if (goalCode != null) body['goal_code'] = goalCode;
    List<String> tmp = [];
    for (var p in accept!) {
      tmp.add(p.value);
    }
    body['accept'] = tmp;
  }

  OutOfBandMessage.fromJson(super.jsonObject) : super.fromJson() {
    if (type != DidcommMessages.invitation) {
      throw Exception('Wrong message type');
    }
    if (from == null) throw FormatException('from property needed');
    if (typ != null && typ != DidcommMessageTyp.plain) {
      throw Exception(
          'Out of band Message is expected to be a Plaintext-message');
    }
    goalCode = body['goal_code'];
    goal = body['goal'];
    if (body.containsKey('accept')) {
      List acc = body['accept'];
      if (acc.isNotEmpty) {
        accept = [];
        for (String a in acc) {
          switch (a) {
            case 'didcomm/aip1':
              accept!.add(DidcommProfiles.aip1);
              break;
            case 'didcomm/aip2;env=rfc19':
              accept!.add(DidcommProfiles.rfc19);
              break;
            case 'didcomm/aip2;env=rfc587':
              accept!.add(DidcommProfiles.rfc587);
              break;
            case 'didcomm/v2':
              accept!.add(DidcommProfiles.v2);
              break;
            default:
              throw Exception('Unknown Profile');
          }
        }
      }
    }
  }

  String toUrl(String protocol, String domain, String path) {
    return '$protocol://$domain/$path?_oob=${base64UrlEncode(utf8.encode(toString()))}';
  }
}

/// Converts Out-of-band message url [url] to OutOfBand message object.
OutOfBandMessage oobMessageFromUrl(String url) {
  var asUri = Uri.parse(url);
  if (asUri.queryParameters.containsKey('_oob')) {
    return OutOfBandMessage.fromJson(utf8.decode(
        base64Decode(addPaddingToBase64(asUri.queryParameters['_oob']!))));
  } else {
    throw Exception('No Out-Of-Band Message found');
  }
}
