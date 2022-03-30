import 'dart:convert';

import 'package:uuid/uuid.dart';

import '../didcomm_jwm.dart';
import '../types.dart';

class EmptyMessage extends DidcommPlaintextMessage {
  EmptyMessage({String? id})
      : super(
            id: id ?? Uuid().v4(),
            type: 'https://didcomm.org/reserved/2.0/empty',
            body: {});

  EmptyMessage.fromJson(dynamic jsonObject) : super.fromJson(jsonObject) {
    if (type != 'https://didcomm.org/reserved/2.0/empty')
      throw Exception('Wrong message type');
    if (body.length > 0) throw Exception('this message is not empty');
  }
}

class ProblemReport extends DidcommPlaintextMessage {
  late String code;
  String? comment;
  List<String>? args;
  String? escalateTo;

  ProblemReport(
      {String? id,
      required String parentThreadId,
      List<String>? ack,
      required this.code,
      this.comment,
      this.args,
      this.escalateTo})
      : super(
            id: id ?? Uuid().v4(),
            type: 'https://didcomm.org/report-problem/2.0/problem-report',
            body: {},
            parentThreadId: parentThreadId,
            ack: ack) {
    body['code'] = code;
    if (comment != null) body['comment'] = comment;
    if (args != null) body['args'] = args;
    if (escalateTo != null) body['escalated_to'] = escalateTo;
  }

  ProblemReport.fromJson(dynamic jsonObject) : super.fromJson(jsonObject) {
    if (type != 'https://didcomm.org/report-problem/2.0/problem-report')
      throw Exception('Wrong message type');
    if (body.containsKey('code'))
      code = body['code'];
    else
      throw FormatException('code property is needed in Problem Report');
    comment = body['comment'];
    args = body['args'];
    escalateTo = body['escalate_to'];
  }

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
        } catch (e) {}
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
      required String from,
      this.goalCode,
      this.goal,
      this.accept = const [DidcommProfiles.v2],
      required List<Attachment> attachments})
      : super(
            id: id ?? Uuid().v4(),
            type: 'https://didcomm.org/out-of-band/2.0/invitation',
            body: {},
            typ: DidcommMessageTyp.plain,
            from: from,
            attachments: attachments) {
    if (goal != null) body['goal'] = goal;
    if (goalCode != null) body['goal_code'] = goalCode;
    List<String> tmp = [];
    for (var p in accept!) tmp.add(p.value);
    body['accept'] = tmp;
  }

  OutOfBandMessage.fromJson(dynamic jsonObject) : super.fromJson(jsonObject) {
    if (type != 'https://didcomm.org/out-of-band/2.0/invitation')
      throw Exception('Wring message type');
    if (from == null || attachments == null || attachments!.length == 0)
      throw FormatException('from and attachments property needed');
    if (typ != null && typ != DidcommMessageTyp.plain)
      throw Exception(
          'Out of band Message is expected to be a Plaintext-message');
    goalCode = body['goal_code'];
    goal = body['goal'];
    if (body.containsKey('accept')) {
      List acc = body['accept'];
      if (acc.length > 0) {
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
    return '$protocol://$domain/$path?_oob=${base64UrlEncode(utf8.encode(this.toString()))}';
  }
}
