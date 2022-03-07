import 'dart:convert';

import '../credential_operations.dart';

class DidcommPlaintextMessage {
  List<dynamic>? to;
  String? from;
  late String id;
  late String type;
  String? typ;
  String? threadId;
  String? parentThreadId;
  DateTime? createdTime;
  DateTime? expiresTime;
  late Map<String, dynamic> body;

  DidcommPlaintextMessage(this.id, this.type, this.body,
      {this.typ,
      this.threadId,
      this.parentThreadId,
      this.createdTime,
      this.expiresTime,
      this.to,
      this.from});

  DidcommPlaintextMessage.fromJson(dynamic message) {
    Map<String, dynamic> decoded = credentialToMap(message);
    id = decoded['id']!;
    type = decoded['type']!;
    body = decoded['body']!;
    from = decoded['from'];
    to = decoded['to'];
    threadId = decoded['thid'];
    parentThreadId = decoded['pthid'];
    typ = decoded['typ'];
    var tmp = decoded['created_time'];
    if (tmp != 0)
      createdTime =
          DateTime.fromMillisecondsSinceEpoch(tmp * 1000, isUtc: true);
    tmp = decoded['expires_time'];
    if (tmp != null)
      expiresTime =
          DateTime.fromMillisecondsSinceEpoch(tmp * 1000, isUtc: true);
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> message = {};
    message['id'] = id;
    message['type'] = type;
    if (from != null) message['from'] = from;
    if (to != null) message['to'] = to;
    if (typ != null) message['typ'] = typ;
    if (threadId != null) message['thid'] = threadId;
    if (parentThreadId != null) message['pthid'] = parentThreadId;
    if (createdTime != null)
      message['created_time'] = createdTime!.millisecondsSinceEpoch ~/ 1000;
    if (expiresTime != null)
      message['expires_time'] = expiresTime!.millisecondsSinceEpoch ~/ 1000;
    message['body'] = body;
    return message;
  }

  String toString() {
    return jsonEncode(toJson());
  }
}
