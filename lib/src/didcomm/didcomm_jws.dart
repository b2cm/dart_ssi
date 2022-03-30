import 'dart:convert';

import 'package:crypto_keys/crypto_keys.dart';
import 'package:dart_web3/crypto.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

import '../util/types.dart';
import '../util/utils.dart';
import 'didcomm_jwe.dart';
import 'didcomm_jwm.dart';
import 'types.dart';

class DidcommSignedMessage implements JsonObject, DidcommMessage {
  late DidcommMessage payload;
  late List<SignatureObject> signatures;
  String? _base64Payload;

  DidcommSignedMessage({required this.payload, required this.signatures});

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
    } else
      throw Exception('payload is needed in jws');
    if (sig.containsKey('signatures')) {
      List tmp = sig['signatures'];
      if (tmp.length > 0) {
        signatures = [];
        for (var s in tmp) {
          signatures.add(SignatureObject.fromJson(s));
        }
      } else
        throw Exception('Empty Signatures');
    } else
      throw Exception('signature property is needed in jws');
  }

  DidcommSignedMessage.sign(
      {required this.payload,
      required List<Map<String, dynamic>> jwkToSignWith}) {
    signatures = [];
    for (var key in jwkToSignWith) {
      signatures.add(_sign(key));
    }
  }

  SignatureObject _sign(Map<String, dynamic> jwkToSignWith) {
    var crv = jwkToSignWith['crv'];
    if (crv == null) throw Exception('Jwk without crv parameter');
    Map<String, dynamic> protected = {'typ': DidcommMessageTyp.signed.value};
    if (crv == 'secp256k1') {
      protected['alg'] = JwsSignatureAlgorithm.es256k.value;
      var privateKey = EcPrivateKey(
          eccPrivateKey: bytesToUnsignedInt(
              base64Decode(addPaddingToBase64(jwkToSignWith['d']))),
          curve: curves.p256k);

      var encodedHeader = removePaddingFromBase64(
          base64UrlEncode(utf8.encode(jsonEncode(protected))));
      var signer = privateKey.createSigner(algorithms.signing.ecdsa.sha256);
      var sig = signer.sign(ascii.encode(
          '$encodedHeader.${_base64Payload ?? removePaddingFromBase64(base64UrlEncode(utf8.encode(payload.toString())))}'));
      return SignatureObject(
          signature: removePaddingFromBase64(base64UrlEncode(sig.data)),
          protected: protected);
    } else if (crv == 'P-256') {
      protected['alg'] = JwsSignatureAlgorithm.es256.value;
      var privateKey = EcPrivateKey(
          eccPrivateKey: bytesToUnsignedInt(
              base64Decode(addPaddingToBase64(jwkToSignWith['d']))),
          curve: curves.p256);

      var encodedHeader = removePaddingFromBase64(
          base64UrlEncode(utf8.encode(jsonEncode(protected))));
      var signer = privateKey.createSigner(algorithms.signing.ecdsa.sha256);
      var sig = signer.sign(ascii.encode(
          '$encodedHeader.${_base64Payload ?? removePaddingFromBase64(base64UrlEncode(utf8.encode(payload.toString())))}'));
      return SignatureObject(
          signature: removePaddingFromBase64(base64UrlEncode(sig.data)),
          protected: protected);
    } else if (crv == 'Ed25519') {
      protected['alg'] = JwsSignatureAlgorithm.edDsa.value;
      var privateKey = ed
          .newKeyFromSeed(base64Decode(addPaddingToBase64(jwkToSignWith['d'])));

      var encodedHeader = removePaddingFromBase64(
          base64UrlEncode(utf8.encode(jsonEncode(protected))));

      var sig = ed.sign(
          privateKey,
          ascii.encode(
              '$encodedHeader.${_base64Payload ?? removePaddingFromBase64(base64UrlEncode(utf8.encode(payload.toString())))}'));
      return SignatureObject(
          signature: removePaddingFromBase64(base64UrlEncode(sig)),
          protected: protected);
    } else
      throw UnimplementedError('Other curves or algorithms are not supported');
  }

  bool verify(Map<String, dynamic> publicKeyJwk) {
    var crv = publicKeyJwk['crv'];
    if (crv == null) throw Exception('Jwk without crv parameter');
    bool valid = true;
    for (var s in signatures) {
      var alg = s.protected!['alg'];
      if (alg == null)
        throw Exception('alg property must be present');
      else if (alg == JwsSignatureAlgorithm.edDsa.value) {
        if (crv != 'Ed25519') throw Exception('wrong curve for algorithm $alg');
        var publicKey =
            ed.PublicKey(base64Decode(addPaddingToBase64(publicKeyJwk['x'])));
        var encodedHeader = removePaddingFromBase64(
            base64UrlEncode(utf8.encode(jsonEncode(s.protected))));
        valid = ed.verify(
            publicKey,
            ascii.encode(
                '$encodedHeader.${_base64Payload ?? removePaddingFromBase64(base64UrlEncode(utf8.encode(payload.toString())))}'),
            base64Decode(addPaddingToBase64(s.signature)));
      } else if (alg == JwsSignatureAlgorithm.es256.value) {
        if (crv != 'P-256') throw Exception('wrong curve for algorithm $alg');
        var pubKey = EcPublicKey(
            xCoordinate: bytesToUnsignedInt(
                base64Decode(addPaddingToBase64(publicKeyJwk['x']))),
            yCoordinate: bytesToUnsignedInt(
                base64Decode(addPaddingToBase64(publicKeyJwk['y']))),
            curve: curves.p256);
        var verifier = pubKey.createVerifier(algorithms.signing.ecdsa.sha256);
        var encodedHeader = removePaddingFromBase64(
            base64UrlEncode(utf8.encode(jsonEncode(s.protected))));
        valid = verifier.verify(
            ascii.encode(
                '$encodedHeader.${_base64Payload ?? removePaddingFromBase64(base64UrlEncode(utf8.encode(payload.toString())))}'),
            Signature(base64Decode(addPaddingToBase64(s.signature))));
      } else if (alg == JwsSignatureAlgorithm.es256k.value) {
        if (crv != 'secp256k1')
          throw Exception('wrong curve for algorithm $alg');
        var pubKey = EcPublicKey(
            xCoordinate: bytesToUnsignedInt(
                base64Decode(addPaddingToBase64(publicKeyJwk['x']))),
            yCoordinate: bytesToUnsignedInt(
                base64Decode(addPaddingToBase64(publicKeyJwk['y']))),
            curve: curves.p256k);
        var verifier = pubKey.createVerifier(algorithms.signing.ecdsa.sha256);
        var encodedHeader = removePaddingFromBase64(
            base64UrlEncode(utf8.encode(jsonEncode(s.protected))));
        valid = verifier.verify(
            ascii.encode(
                '$encodedHeader.${_base64Payload ?? removePaddingFromBase64(base64UrlEncode(utf8.encode(payload.toString())))}'),
            Signature(base64Decode(addPaddingToBase64(s.signature))));
      } else
        throw UnimplementedError('Other signing algorithms are not supported');
    }
    return valid;
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['payload'] = removePaddingFromBase64(
        base64UrlEncode(utf8.encode(payload.toString())));
    List sigs = [];
    for (var s in signatures) {
      sigs.add(s.toJson());
    }
    jsonObject['signatures'] = sigs;
    return jsonObject;
  }

  String toString() {
    return jsonEncode(toJson());
  }
}

class SignatureObject implements JsonObject {
  Map<String, dynamic>? protected;
  Map<String, dynamic>? header;
  late String signature;

  SignatureObject({this.protected, this.header, required this.signature});

  SignatureObject.fromJson(dynamic jsonObject) {
    var sig = credentialToMap(jsonObject);
    if (sig.containsKey('protected'))
      protected = jsonDecode(
          utf8.decode(base64Decode(addPaddingToBase64(sig['protected']!))));
    header = sig['header'];
    if (sig.containsKey('signature'))
      signature = sig['signature'];
    else
      throw Exception('signature value is needed in SignatureObject');
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (protected != null)
      jsonObject['protected'] = removePaddingFromBase64(
          base64UrlEncode(utf8.encode(jsonEncode(protected!))));
    if (header != null) jsonObject['header'] = header;
    jsonObject['signature'] = signature;
    return jsonObject;
  }

  String toString() {
    return jsonEncode(toJson());
  }
}
