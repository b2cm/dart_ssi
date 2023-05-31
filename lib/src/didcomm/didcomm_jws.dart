import 'dart:convert';

import 'package:json_ld_processor/json_ld_processor.dart';
import 'package:json_schema2/json_schema2.dart';

import '../credentials/credential_operations.dart';
import '../credentials/credential_signer.dart' as signer;
import '../util/types.dart';
import '../util/utils.dart';
import 'didcomm_jwe.dart';
import 'didcomm_jwm.dart';
import 'types.dart';

var signedMessageSchema = JsonSchema.createSchema({
  'type': 'object',
  'properties': {
    'payload': {'type': 'string'},
    'signatures': {
      'type': 'array',
      'contains': {
        'type': 'object',
        'properties': {
          'signature': {
            'type': 'string',
          },
          'header': {'type': 'object'},
          'protected': {'type': 'string'}
        },
        'required': ['signature']
      }
    }
  },
  'required': ['payload', 'signatures']
});

bool isSignedMessage(dynamic message) {
  var asMap = credentialToMap(message);
  return signedMessageSchema.validate(asMap);
}

/// A signed didcomm message
class DidcommSignedMessage implements JsonObject, DidcommMessage {
  late DidcommMessage payload;
  List<SignatureObject>? signatures;
  String? _base64Payload;

  DidcommSignedMessage({required this.payload, this.signatures});

  DidcommSignedMessage.fromJson(dynamic jsonObject) {
    var sig = credentialToMap(jsonObject);
    if (sig.containsKey('payload')) {
      _base64Payload = sig['payload'];
      var decodedPayload =
          utf8.decode(base64Decode(addPaddingToBase64(sig['payload'])));
      try {
        payload = DidcommSignedMessage.fromJson(decodedPayload);
      } catch (e) {
        try {
          payload = DidcommPlaintextMessage.fromJson(decodedPayload);
        } catch (e) {
          try {
            payload = DidcommEncryptedMessage.fromJson(decodedPayload);
          } catch (e) {
            throw Exception('Unknown message type');
          }
        }
      }
    } else {
      throw Exception('payload is needed in jws');
    }
    if (sig.containsKey('signatures')) {
      List tmp = sig['signatures'];
      if (tmp.isNotEmpty) {
        signatures = [];
        for (var s in tmp) {
          signatures!.add(SignatureObject.fromJson(s));
        }
      } else {
        throw Exception('Empty Signatures');
      }
    } else {
      throw Exception('signature property is needed in jws');
    }
  }

  signer.Signer _determineSignerForJwk(Map<String, dynamic> jwk,
      Function(Uri url, LoadDocumentOptions? options)? loadDocumentFunction) {
    if (jwk['crv'] == 'P-256') {
      return signer.Es256Signer();
    } else if (jwk['crv'] == 'Ed25519') {
      return signer.EdDsaSigner(loadDocumentFunction);
    } else if (jwk['crv'] == 'secp256k1') {
      return signer.Es256k1Signer();
    } else {
      throw Exception('could not examine signer');
    }
  }

  Future<void> sign(List<Map<String, dynamic>> jwkToSignWith) async {
    signatures ??= [];
    for (var jwk in jwkToSignWith) {
      var signerImpl = _determineSignerForJwk(jwk, null);
      Map<String, dynamic> protected = {
        'typ': DidcommMessageTyp.signed.value,
        'alg': signerImpl.algValue,
        'crv': signerImpl.crvValue
      };
      var jws = await signStringOrJson(
          jwk: jwk,
          jwsHeader: protected,
          signer: signerImpl,
          toSign: _base64Payload != null
              ? utf8.decode(base64Decode(_base64Payload!))
              : payload.toJson(),
          detached: true);
      signatures!.add(SignatureObject(
          signature: jws.split('..').last, protected: protected));
    }
    return;
  }

  Future<bool> verify(Map<String, dynamic> publicKeyJwk) async {
    var crv = publicKeyJwk['crv'];
    if (crv == null) throw Exception('Jwk without crv parameter');
    bool valid = true;

    if (signatures == null || signatures!.isEmpty) {
      throw Exception('Nothing to verify');
    }

    for (var s in signatures!) {
      var encodedHeader = removePaddingFromBase64(
          base64UrlEncode(utf8.encode(jsonEncode(s.protected))));
      var encodedPayload = _base64Payload ??
          removePaddingFromBase64(
              base64UrlEncode(utf8.encode(payload.toString())));
      var encodedSignature = s.signature;
      valid = await verifyStringSignature(
          '$encodedHeader.$encodedPayload.$encodedSignature',
          jwk: publicKeyJwk);
      if (!valid) {
        throw Exception('A Signature is wrong');
      }
    }
    return valid;
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['payload'] = removePaddingFromBase64(
        base64UrlEncode(utf8.encode(payload.toString())));

    if (signatures != null) {
      List sigs = [];
      for (var s in signatures!) {
        sigs.add(s.toJson());
      }
      jsonObject['signatures'] = sigs;
    }

    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

/// Signature of a didcomm signed message
class SignatureObject implements JsonObject {
  Map<String, dynamic>? protected;
  Map<String, dynamic>? header;
  late String signature;

  SignatureObject({this.protected, this.header, required this.signature});

  SignatureObject.fromJson(dynamic jsonObject) {
    var sig = credentialToMap(jsonObject);
    if (sig.containsKey('protected')) {
      protected = jsonDecode(
          utf8.decode(base64Decode(addPaddingToBase64(sig['protected']!))));
    }
    header = sig['header'];
    if (sig.containsKey('signature')) {
      signature = sig['signature'];
    } else {
      throw Exception('signature value is needed in SignatureObject');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (protected != null) {
      jsonObject['protected'] = removePaddingFromBase64(
          base64UrlEncode(utf8.encode(jsonEncode(protected!))));
    }
    if (header != null) jsonObject['header'] = header;
    jsonObject['signature'] = signature;
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
