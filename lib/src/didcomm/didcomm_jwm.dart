import 'dart:convert';

import '../credentials/credential_operations.dart';
import '../util/types.dart';

class DidcommPlaintextMessage implements JsonObject {
  List<dynamic>? to;
  String? from;
  late String id;
  late String type;
  DidcommMessageTyp? typ;
  String? threadId;
  String? parentThreadId;
  DateTime? createdTime;
  DateTime? expiresTime;
  late Map<String, dynamic> body;
  FromPriorJWT? fromPrior;
  List<Attachment>? attachments;

  /// The header’s value is an array of strings that clarify when the ACK is
  /// requested. Only the following value is defined by this version of
  /// the spec: “receipt”.
  List<String>? pleaseAck;

  ///  the value of the header is an array that contains the id of one or more
  ///  messages being acknowledged. Values in this array MUST appear in the
  ///  order received, from oldest to most recent.
  List<String>? ack;

  DidcommPlaintextMessage(
      {required this.id,
      required this.type,
      required this.body,
      this.typ,
      this.threadId,
      this.parentThreadId,
      this.createdTime,
      this.expiresTime,
      this.to,
      this.from,
      this.fromPrior,
      this.attachments,
      bool pleaseAck = false,
      this.ack}) {
    if (pleaseAck) this.pleaseAck = ['receipt'];
  }

  DidcommPlaintextMessage.fromJson(dynamic message) {
    Map<String, dynamic> decoded = credentialToMap(message);
    id = decoded['id']!;
    type = decoded['type']!;
    if (decoded.containsKey('body'))
      body = decoded['body']!;
    else {
      body = {};
      if (type != 'https://didcomm.org/reserved/2.0/empty')
        throw Exception('Empty Body only allowed in Empty Message');
    }
    from = decoded['from'];
    to = decoded['to'];
    threadId = decoded['thid'];
    parentThreadId = decoded['pthid'];
    if (decoded.containsKey('typ')) {
      String typTmp = decoded['typ'];
      switch (typTmp) {
        case 'application/didcomm-plain+json':
          typ = DidcommMessageTyp.plain;
          break;
        case 'application/didcomm-signed+json':
          typ = DidcommMessageTyp.signed;
          break;
        case 'application/didcomm-encrypted+json':
          typ = DidcommMessageTyp.encrypted;
          break;
        default:
          throw Exception('Unknown typ');
      }
    }
    var tmp = decoded['created_time'];
    if (tmp != null)
      createdTime =
          DateTime.fromMillisecondsSinceEpoch(tmp * 1000, isUtc: true);
    tmp = decoded['expires_time'];
    if (tmp != null)
      expiresTime =
          DateTime.fromMillisecondsSinceEpoch(tmp * 1000, isUtc: true);

    if (decoded.containsKey('from_prior')) {
      fromPrior = FromPriorJWT.fromCompactSerialization(decoded['from_prior']);
      if (fromPrior != null && from != null) {
        if (from != fromPrior!.sub)
          throw Exception('from value must match from_prior.sub');
      }
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
    pleaseAck = decoded['please_ack'];
    ack = decoded['ack'];
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> message = {};
    message['id'] = id;
    message['type'] = type;
    if (from != null) message['from'] = from;
    if (to != null) message['to'] = to;
    if (typ != null) message['typ'] = typ!.value;
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
    if (pleaseAck != null) message['please_ack'] = pleaseAck;
    if (ack != null) message['ack'] = ack;
    return message;
  }

  String toString() {
    return jsonEncode(toJson());
  }
}

class Attachment implements JsonObject {
  String? id;
  String? description;
  String? filename;
  String? mediaType;
  String? format;
  DateTime? lastmodTime;
  int? byteCount;
  late AttachmentData data;

  Attachment(
      {required this.data,
      this.id,
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

class AttachmentData implements JsonObject {
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
    if (base64 != null)
      json = jsonDecode(utf8.decode(base64Decode(addPaddingToBase64(base64!))));
    else
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

  FromPriorJWT(
      {required this.sub,
      required this.iss,
      required this.iat,
      required this.curve,
      required this.alg,
      required this.kid,
      required this.signature});

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

enum DidcommProfiles { aip1, rfc19, rfc587, v2 }

extension DidcommProfileExt on DidcommProfiles {
  static const Map<DidcommProfiles, String> values = {
    DidcommProfiles.aip1: 'didcomm/aip1',
    DidcommProfiles.rfc19: 'didcomm/aip2;env=rfc19',
    DidcommProfiles.rfc587: 'didcomm/aip2;env=rfc587',
    DidcommProfiles.v2: 'didcomm/v2'
  };
  String get value => values[this]!;
}

enum DidcommMessageTyp { plain, signed, encrypted }

extension DidcommMessageTypExt on DidcommMessageTyp {
  static const Map<DidcommMessageTyp, String> values = {
    DidcommMessageTyp.plain: 'application/didcomm-plain+json',
    DidcommMessageTyp.signed: 'application/didcomm-signed+json',
    DidcommMessageTyp.encrypted: 'application/didcomm-encrypted+json'
  };
  String get value => values[this]!;
}
