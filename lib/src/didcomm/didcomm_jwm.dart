import 'dart:convert';
import 'dart:io';

import '../credentials/credential_operations.dart';
import '../util/types.dart';
import '../util/utils.dart';
import '../wallet/wallet_store.dart';
import 'types.dart';

/// A plaintext-Message (json-web message) as per didcomm specification
class DidcommPlaintextMessage implements JsonObject, DidcommMessage {
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
  Map<String, dynamic>? additionalHeaders;
  List<String>? pleaseAck;
  List<String>? ack;
  String? replyUrl;
  List<String>? replyTo;
  WebRedirect? webRedirect;

  DidcommPlaintextMessage(
      {required this.id,
      required this.type,
      required this.body,
      this.replyUrl,
      this.replyTo,
      this.typ,
      String? threadId,
      this.parentThreadId,
      this.createdTime,
      this.expiresTime,
      this.to,
      this.from,
      this.fromPrior,
      this.attachments,
      bool pleaseAck = false,
      this.ack,
      this.webRedirect,
      this.additionalHeaders}) {
    if (pleaseAck) this.pleaseAck = ['receipt'];
    this.threadId = threadId ?? id;
  }

  DidcommPlaintextMessage.fromJson(dynamic message) {
    Map<String, dynamic> decoded = credentialToMap(message);
    id = decoded['id']!;
    type = decoded['type']!;
    replyUrl = decoded['reply_url'];
    if (decoded.containsKey('reply_to'))
      replyTo = decoded['reply_to'].cast<String>();
    if (decoded.containsKey('body'))
      body = decoded['body']!;
    else {
      body = {};
      if (type != 'https://didcomm.org/empty/1.0')
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
          throw Exception('Unknown typ field ${typTmp}');
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

    if (decoded.containsKey('attachments')) {
      List tmp = decoded['attachments'];
      if (tmp.length > 0) {
        attachments = [];
        for (var a in tmp) {
          attachments!.add(Attachment.fromJson(a));
        }
      }
    }
    if (decoded.containsKey('please_ack'))
      pleaseAck = decoded['please_ack'].cast<String>();
    if (decoded.containsKey('ack')) ack = decoded['ack'].cast<String>();

    if (decoded.containsKey('web_redirect')) {
      webRedirect = WebRedirect.fromJson(decoded['web_redirect']);
    }

    decoded.remove('to');
    decoded.remove('from');
    decoded.remove('id');
    decoded.remove('type');
    decoded.remove('typ');
    decoded.remove('thid');
    decoded.remove('pthid');
    decoded.remove('created_time');
    decoded.remove('expires_time');
    decoded.remove('body');
    decoded.remove('from_prior');
    decoded.remove('attachments');
    decoded.remove('ack');
    decoded.remove('please_ack');
    decoded.remove('reply_to');
    decoded.remove('reply_url');
    decoded.remove('web_redirect');
    if (decoded.length > 0) additionalHeaders = decoded;
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> message = {};
    message['id'] = id;
    if (typ != null) message['typ'] = typ!.value;
    message['type'] = type;
    if (from != null) message['from'] = from;
    if (to != null) message['to'] = to;
    if (threadId != null) message['thid'] = threadId;
    if (parentThreadId != null) message['pthid'] = parentThreadId;
    if (createdTime != null)
      message['created_time'] = createdTime!.millisecondsSinceEpoch ~/ 1000;
    if (expiresTime != null)
      message['expires_time'] = expiresTime!.millisecondsSinceEpoch ~/ 1000;

    if (pleaseAck != null) message['please_ack'] = pleaseAck;
    if (ack != null) message['ack'] = ack;
    if (additionalHeaders != null) message.addAll(additionalHeaders!);
    message['body'] = body;

    //TODO: from_prior header

    if (attachments != null) {
      List<Map<String, dynamic>> tmp = [];
      for (var a in attachments!) tmp.add(a.toJson());
      message['attachments'] = tmp;
    }

    if (replyUrl != null) message['reply_url'] = replyUrl;
    if (replyTo != null) message['reply_to'] = replyTo;

    return message;
  }

  String toString() {
    return jsonEncode(toJson());
  }
}

/// Attachment for a didcomm message
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

/// represents the data in a didcomm message attachment
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

  //TODO check hash
  Future<void> resolveData() async {
    if (json != null)
      return; //Nothing to resolve
    else if (base64 != null)
      json = jsonDecode(utf8.decode(base64Decode(addPaddingToBase64(base64!))));
    else if (links != null && links!.isNotEmpty) {
      if (hash == null) throw Exception('If links are used hash must be given');
      for (var link in links!) {
        try {
          var client = await HttpClient()
              .getUrl(Uri.parse(link))
              .timeout(Duration(seconds: 15));
          var res = await client.close();
          if (res.statusCode == 200) {
            var contents = StringBuffer();
            await for (var data in res.transform(utf8.decoder)) {
              contents.write(data);
            }
            json = jsonDecode(contents.toString());
            break;
          }
        } catch (e) {}
      }
      if (json == null) throw Exception('No data found');
    } else
      throw Exception('No data');
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

  //TODO: for now sign and verify only support json encodeable content
  Future<void> sign(WalletStore wallet, didToSignWith) async {
    Map<String, dynamic> payload;
    if (json != null)
      payload = json!;
    else if (base64 != null)
      payload =
          jsonDecode(utf8.decode(base64Decode(addPaddingToBase64(base64!))));
    else
      throw Exception('nothing to sign');
    jws =
        await signStringOrJson(wallet, didToSignWith, payload, detached: true);
  }

  Future<bool> verifyJws(String expectedDid) async {
    if (jws == null) throw Exception('no signature found');
    Map<String, dynamic> payload;
    if (json != null)
      payload = json!;
    else if (base64 != null)
      payload =
          jsonDecode(utf8.decode(base64Decode(addPaddingToBase64(base64!))));
    else
      throw Exception('nothing to sign');
    return verifyStringSignature(jws, expectedDid, toSign: payload);
  }
}

/// json-web token used in form_prior header of didcomm message. (Not fully implemented)
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

class WebRedirect implements JsonObject {
  late String redirectUrl;
  late AcknowledgeStatus status;

  WebRedirect({required this.redirectUrl, required this.status});

  WebRedirect.fromJson(dynamic jsonObject) {
    Map<String, dynamic> json = credentialToMap(jsonObject);
    if (json.containsKey('status')) {
      String s = json['status'];
      switch (s) {
        case 'FAIL':
          status = AcknowledgeStatus.fail;
          break;
        case 'OK':
          status = AcknowledgeStatus.ok;
          break;
        case 'PENDING':
          status = AcknowledgeStatus.pending;
          break;
        default:
          throw Exception('Unknown Status');
      }
    } else {
      throw Exception('status attribute is needed');
    }

    if (json.containsKey('redirectUrl')) {
      redirectUrl = json['redirectUrl'];
    } else {
      throw Exception('redirectUrl is needed');
    }
  }

  Map<String, dynamic> toJson() {
    return {'status': status.value, 'redirectUrl': redirectUrl};
  }

  String toString() {
    return jsonEncode(toJson());
  }
}
