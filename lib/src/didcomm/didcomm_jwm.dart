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
  FromPriorJWT? fromPrior;
  List<Attachment>? attachments;

  DidcommPlaintextMessage(this.id, this.type, this.body,
      {this.typ,
      this.threadId,
      this.parentThreadId,
      this.createdTime,
      this.expiresTime,
      this.to,
      this.from,
      this.fromPrior,
      this.attachments});

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
    if (tmp != null)
      createdTime =
          DateTime.fromMillisecondsSinceEpoch(tmp * 1000, isUtc: true);
    tmp = decoded['expires_time'];
    if (tmp != null)
      expiresTime =
          DateTime.fromMillisecondsSinceEpoch(tmp * 1000, isUtc: true);

    fromPrior = FromPriorJWT.fromCompactSerialization(decoded['from_prior']);
    if (fromPrior != null && from != null) {
      if (from != fromPrior!.sub)
        throw Exception('from value must match from_prior.sub');
    }

    if (decoded.containsKey(['attachments'])) {
      List tmp = decoded['attachments'];
      if (tmp.length > 0) {
        attachments = [];
        for (var a in tmp) {
          attachments!.add(Attachment.fromJson(a));
        }
      }
    }
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

    //TODO: from_prior header

    if (attachments != null) {
      List<Map<String, dynamic>> tmp = [];
      for (var a in attachments!) tmp.add(a.toJson());
      message['attachments'] = tmp;
    }
    return message;
  }

  String toString() {
    return jsonEncode(toJson());
  }
}

class Attachment {
  String? id;
  String? description;
  String? filename;
  String? mediaType;
  String? format;
  DateTime? lastmodTime;
  int? byteCount;
  late AttachmentData data;

  Attachment(this.data,
      {this.id,
      this.description,
      this.filename,
      this.mediaType,
      this.format,
      this.lastmodTime,
      this.byteCount});

  Attachment.fromJson(dynamic jsonData) {
    Map<String, dynamic> decoded = credentialToMap(jsonData);
    if (decoded.containsKey('data'))
      data = AttachmentData.fromJson(decoded['data']);
    else
      throw FormatException('an Attachment must contain a data property');

    id = decoded['id'];
    description = decoded['description'];
    filename = decoded['filename'];
    mediaType = decoded['media_type'];
    format = decoded['format'];
    if (decoded.containsKey('lastmod_time'))
      lastmodTime = DateTime.fromMillisecondsSinceEpoch(
          decoded['lastmod_time'] * 1000,
          isUtc: true);
    byteCount = decoded['byte_count'];
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonData = {};
    jsonData['data'] = data.toJson();
    if (id != null) jsonData['id'] = id;
    if (description != null) jsonData['description'] = description;
    if (filename != null) jsonData['filename'] = filename;
    if (mediaType != null) jsonData['media_type'] = mediaType;
    if (format != null) jsonData['format'] = format;
    if (lastmodTime != null)
      jsonData['lastmod_time'] = lastmodTime!.millisecondsSinceEpoch ~/ 1000;
    if (byteCount != null) jsonData['byte_count'] = byteCount;
    return jsonData;
  }

  String toString() {
    return jsonEncode(toJson());
  }
}

class AttachmentData {
  dynamic jws;
  String? hash;
  List<String>? links;
  String? base64;
  Map<String, dynamic>? json;

  AttachmentData({this.jws, this.hash, this.links, this.base64, this.json});

  AttachmentData.fromJson(dynamic jsonData) {
    Map<String, dynamic> decoded = credentialToMap(jsonData);
    jws = decoded['jws'];
    hash = decoded['hash'];
    if (decoded.containsKey('links')) links = decoded['links'].cast<String>();
    base64 = decoded['base64'];
    json = decoded['json'];
  }

  //TODO write this function: resolve Data from links; decode base64; check hash -> store everything in json;
  void resolveData() {
    throw UnimplementedError('could not resolve link-data for now');
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonData = {};
    if (jws != null) jsonData['jws'] = jws;
    if (hash != null) jsonData['hash'] = hash;
    if (links != null) jsonData['links'] = links;
    if (base64 != null) jsonData['base64'] = base64;
    if (json != null) jsonData['json'] = json;
    return jsonData;
  }

  String toString() {
    return jsonEncode(toJson());
  }

  //TODO: verify jws from Attachment
  bool _verifyJws() {
    return true;
  }
}

class FromPriorJWT {
  final String typ = 'JWT';
  late String sub;
  late String iss;
  late DateTime iat;
  late String kid;
  late String alg;
  late String curve;
  late String signature;

  FromPriorJWT(this.sub, this.iss, this.iat, this.curve, this.alg, this.kid,
      this.signature);

  FromPriorJWT.fromCompactSerialization(String jwtCompact) {
    var splitted = jwtCompact.split('.');
    if (splitted.length != 3)
      throw FormatException(
          'compact serialization must consist of three parts separated by point(.).');
    Map<String, dynamic> header =
        jsonDecode(utf8.decode(base64Decode(addPaddingToBase64(splitted[0]))));
    Map<String, dynamic> payload =
        jsonDecode(utf8.decode(base64Decode(addPaddingToBase64(splitted[1]))));
    signature = splitted[2];

    if (header['typ'] != typ) throw FormatException('typ value must be JWT');
    alg = header['alg'];
    curve = header['crv'];
    kid = header['kid'];

    sub = payload['sub']!;
    iss = payload['iss']!;
    iat =
        DateTime.fromMillisecondsSinceEpoch(payload['iat'] * 1000, isUtc: true);

    //TODO: check signature
  }

  //TODO: Method to build this header
  String build() {
    return '';
  }
}
