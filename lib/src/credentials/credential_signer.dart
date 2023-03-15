import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:crypto/crypto.dart';
import 'package:crypto_keys/crypto_keys.dart';
import 'package:dart_ssi/did.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:json_ld_processor/json_ld_processor.dart';
import 'package:web3dart/credentials.dart';
import 'package:web3dart/crypto.dart' as web3_crypto;

import '../util/utils.dart';
import '../wallet/wallet_store.dart';
import 'credential_operations.dart';
import 'jsonLdContext/ecdsa_recovery_2020.dart';
import 'jsonLdContext/ed25519_signature.dart';

abstract class Signer {
  final String algValue = '';
  final String crvValue = '';
  final String typeName = '';

  /// Build a LinkedDataProof / DataIntegrityProof
  FutureOr<Map<String, dynamic>> buildProof(
      dynamic data, WalletStore wallet, String did,
      {String? challenge, String? domain, String? proofPurpose});

  /// Build a (detached) JWS
  ///
  /// Either using a combination of [wallet] and [did] **or** by using a private JsonWebKey [jwk].
  FutureOr<String> sign(
      {dynamic data,
      WalletStore? wallet,
      String? did,
      Map<String, dynamic>? jwk,
      bool detached = false,
      dynamic jwsHeader});

  /// Verifies a LinkedDataProof / DataIntegrityProof
  FutureOr<bool> verifyProof(dynamic proof, dynamic data, String did,
      {String? challenge});

  /// Verifies a (detached) JWS
  FutureOr<bool> verify(String jws,
      {String? did, Map<String, dynamic>? jwk, dynamic data});
}

class EcdsaRecoverySignature implements Signer {
  @override
  final String typeName = 'EcdsaSecp256k1RecoverySignature2020';
  @override
  final String algValue = 'ES256K-R';
  @override
  final String crvValue = 'secp256k1';
  final Function(Uri url, LoadDocumentOptions? options)? loadDocument;

  EcdsaRecoverySignature(this.loadDocument);

  @override
  Future<Map<String, dynamic>> buildProof(data, WalletStore wallet, String did,
      {String? challenge, String? domain, String? proofPurpose}) async {
    var proofOptions = {
      '@context': ecdsaRecoveryContextIri,
      'type': typeName,
      'proofPurpose': proofPurpose ?? 'assertionMethod',
      'verificationMethod': '$did#controller',
      'created': DateTime.now().toUtc().toIso8601String()
    };
    if (domain != null) {
      proofOptions['domain'] = domain;
    }
    if (challenge != null) {
      proofOptions['challenge'] = challenge;
    }

    List<int> hashToSign = await _dataToHash(data);

    var pOptionsHash = sha256
        .convert(utf8.encode(await JsonLdProcessor.normalize(proofOptions,
            options:
                JsonLdOptions(safeMode: true, documentLoader: loadDocument))))
        .bytes;
    var hash = sha256.convert(pOptionsHash + hashToSign).bytes;

    proofOptions.remove('@context');

    var privateKeyHex = await wallet.getPrivateKeyForCredentialDid(did);
    privateKeyHex ??= await wallet.getPrivateKeyForConnectionDid(did);
    if (privateKeyHex == null) throw Exception('Could not find a private key');
    var key = EthPrivateKey.fromHex(privateKeyHex);

    var sigArray = _buildSignatureArray(Uint8List.fromList(hash), key);
    while (sigArray.length != 65) {
      sigArray = _buildSignatureArray(Uint8List.fromList(hash), key);
    }

    var critical = <String, dynamic>{};
    critical['b64'] = false;
    proofOptions['jws'] = '${buildJwsHeader(alg: 'ES256K-R', extra: critical)}.'
        '.${base64UrlEncode(sigArray)}';

    return proofOptions;
  }

  FutureOr<List<int>> _dataToHash(dynamic data) async {
    if (data is Uint8List) {
      return data.toList();
    } else if (data is List<int>) {
      return data;
    } else if (data is Map<String, dynamic>) {
      return sha256
          .convert(utf8.encode(await JsonLdProcessor.normalize(
              Map<String, dynamic>.from(data),
              options:
                  JsonLdOptions(safeMode: true, documentLoader: loadDocument))))
          .bytes;
    } else if (data is String) {
      return sha256.convert(utf8.encode(data)).bytes;
    } else {
      throw Exception('Unknown datatype for data');
    }
  }

  @override
  Future<String> sign(
      {dynamic data,
      WalletStore? wallet,
      String? did,
      Map<String, dynamic>? jwk,
      bool detached = false,
      dynamic jwsHeader}) async {
    String header;
    if (jwsHeader != null) {
      Map<String, dynamic>? headerMap;
      if (jwsHeader is String) {
        headerMap = jsonDecode(jwsHeader);
      } else {
        headerMap = jwsHeader;
      }
      if (headerMap!['alg'] != 'ES256K-R') {
        throw Exception('Unsupported signature algorithm ${headerMap['alg']}');
      }
      header = removePaddingFromBase64(
          base64UrlEncode(utf8.encode(jsonEncode(headerMap))));
    } else {
      var critical = <String, dynamic>{};
      critical['b64'] = false;
      header = removePaddingFromBase64(
          buildJwsHeader(alg: 'ES256K-R', extra: critical));
    }

    String signable = '';
    if (data is String) {
      signable = data;
    } else if (data is Map<String, dynamic>) {
      signable = jsonEncode(data);
    } else {
      throw Exception('Unexpected Datatype ${data.runtimeType} for toSign');
    }

    var payload =
        removePaddingFromBase64(base64UrlEncode(utf8.encode(signable)));
    var signingInput = '$header.$payload';
    var hash = sha256.convert(ascii.encode(signingInput)).bytes;
    String? privateKeyHex;

    if (did != null && wallet != null) {
      privateKeyHex = await wallet.getPrivateKeyForCredentialDid(did);
      privateKeyHex ??= await wallet.getPrivateKeyForConnectionDid(did);
      if (privateKeyHex == null) throw Exception('Could not find private key');
    } else if (jwk != null) {
      if (jwk['crv'] != 'secp256k1') {
        throw Exception('Wrong crv value for private key');
      }

      if (jwk['d'] == null) {
        throw Exception('This is no private key');
      }

      privateKeyHex = hexEncode(
          Uint8List.fromList(base64Decode(addPaddingToBase64(jwk['d']))));
    } else {
      throw Exception('No private key given. Can\'t sign data');
    }

    var key = EthPrivateKey.fromHex(privateKeyHex);
    var sigArray = _buildSignatureArray(hash as Uint8List, key);
    while (sigArray.length != 65) {
      sigArray = _buildSignatureArray(hash, key);
    }

    if (detached) {
      return '$header.'
          '.${removePaddingFromBase64(base64UrlEncode(sigArray))}';
    } else {
      return '$header.$payload'
          '.${removePaddingFromBase64(base64UrlEncode(sigArray))}';
    }
  }

  List<int> _buildSignatureArray(Uint8List hash, EthPrivateKey privateKey) {
    web3_crypto.MsgSignature signature =
        web3_crypto.sign(hash, privateKey.privateKey);
    List<int> rList = web3_crypto.unsignedIntToBytes(signature.r);
    if (rList.length < 32) {
      List<int> rPad = List.filled(32 - rList.length, 0);
      rList = rPad + rList;
    }
    List<int> sList = web3_crypto.unsignedIntToBytes(signature.s);
    if (sList.length < 32) {
      List<int> sPad = List.filled(32 - sList.length, 0);
      sList = sPad + sList;
    }
    List<int> sigArray = rList + sList + [signature.v - 27];
    return sigArray;
  }

  @override
  Future<bool> verifyProof(proof, data, String did, {String? challenge}) async {
    //compare challenge
    if (challenge != null) {
      var containedChallenge = proof['challenge'];
      if (containedChallenge == null) {
        throw Exception('Expected challenge in this credential');
      }
      if (containedChallenge != challenge) {
        throw Exception('a challenge do not match expected challenge');
      }
    }

    //verify signature
    var signature = _getSignatureFromJws(proof['jws']);

    List<int> hash = await _dataToHash(data);

    var jws = proof.remove('jws');
    proof['@context'] = ecdsaRecoveryContextIri;
    var proofHash = sha256
        .convert(utf8.encode(await JsonLdProcessor.normalize(proof,
            options:
                JsonLdOptions(safeMode: true, documentLoader: loadDocument))))
        .bytes;
    var hashToSign = sha256.convert(proofHash + hash).bytes;

    proof['jws'] = jws;
    proof.remove('@context');

    var pubKey = web3_crypto.ecRecover(hashToSign as Uint8List, signature);

    var givenAddress = EthereumAddress.fromHex(did.split(':').last);

    return EthereumAddress.fromPublicKey(pubKey).hexEip55 ==
        givenAddress.hexEip55;
  }

  web3_crypto.MsgSignature _getSignatureFromJws(String jws) {
    var splitJws = jws.split('.');
    Map<String, dynamic> header =
        jsonDecode(utf8.decode(base64Decode(addPaddingToBase64(splitJws[0]))));
    if (header['alg'] != 'ES256K-R') {
      throw Exception('Unsupported signature Algorithm ${header['alg']}');
    }
    var sigArray = base64Decode(addPaddingToBase64(splitJws[2]));
    if (sigArray.length != 65) throw Exception('wrong signature-length');
    return web3_crypto.MsgSignature(
        web3_crypto.bytesToUnsignedInt(sigArray.sublist(0, 32)),
        web3_crypto.bytesToUnsignedInt(sigArray.sublist(32, 64)),
        sigArray[64] + 27);
  }

  @override
  FutureOr<bool> verify(String jws,
      {String? did, Map<String, dynamic>? jwk, dynamic data}) {
    var splitted = jws.split('.');
    if (splitted.length != 3) throw Exception('Malformed JWS');
    var signature = _getSignatureFromJws(jws);

    String payload;
    if (splitted[1] != '') {
      payload = splitted[1];
    } else if (data != null) {
      String signable = '';
      if (data is String) {
        signable = data;
      } else if (data is Map<String, dynamic>) {
        signable = jsonEncode(data);
      } else {
        throw Exception('Unexpected Datatype ${data.runtimeType} for toSign');
      }
      payload = removePaddingFromBase64(base64UrlEncode(utf8.encode(signable)));
    } else {
      throw Exception('No payload given');
    }

    var signingInput = '${splitted[0]}.$payload';
    var hashToSign = sha256.convert(ascii.encode(signingInput)).bytes;
    var pubKey = web3_crypto.ecRecover(hashToSign as Uint8List, signature);

    if (did != null) {
      return EthereumAddress.fromPublicKey(pubKey).hexEip55 ==
          did.split(':').last;
    } else if (jwk != null) {
      // TODO: Check if it works
      return EthereumAddress.fromPublicKey(pubKey).hexEip55 ==
          EthereumAddress.fromPublicKey(Uint8List.fromList(
                  base64Decode(addPaddingToBase64(jwk['x']))))
              .hexEip55;
    } else {
      throw Exception('Either did or jwk must be given');
    }
  }
}

class EdDsaSigner implements Signer {
  @override
  final String typeName = 'Ed25519Signature2020';
  final Function(Uri url, LoadDocumentOptions? options)? loadDocument;
  @override
  final String algValue = 'EdDSA';
  @override
  final String crvValue = 'Ed25519';

  EdDsaSigner(this.loadDocument);

  @override
  FutureOr<Map<String, dynamic>> buildProof(
      data, WalletStore wallet, String did,
      {String? challenge, String? domain, String? proofPurpose}) async {
    var proofOptions = {
      '@context': ed25519ContextIri,
      'type': typeName,
      'proofPurpose': proofPurpose ?? 'assertionMethod',
      'verificationMethod': '$did#${did.split(':')[2]}',
      'created': DateTime.now().toUtc().toIso8601String()
    };
    if (domain != null) {
      proofOptions['domain'] = domain;
    }
    if (challenge != null) {
      proofOptions['challenge'] = challenge;
    }
    String pOptions = await JsonLdProcessor.normalize(proofOptions,
        options: JsonLdOptions(safeMode: true, documentLoader: loadDocument));

    proofOptions.remove('@context');

    List<int> hashToSign = await _dataToHash(data);

    var pOptionsHash = sha256.convert(utf8.encode(pOptions)).bytes;
    var hash = pOptionsHash + hashToSign;
    //print(hash);

    var privateKey = await wallet.getPrivateKeyForCredentialDid(did);
    privateKey ??= await wallet.getPrivateKeyForConnectionDid(did);
    if (privateKey == null) throw Exception('Could not find a private key');
    var signature = ed.sign(
        ed.PrivateKey(web3_crypto.hexToBytes(privateKey).toList()),
        Uint8List.fromList(hash));

    proofOptions['proofValue'] = 'z${base58BitcoinEncode(signature)}';

    return proofOptions;
  }

  FutureOr<List<int>> _dataToHash(dynamic data) async {
    if (data is Uint8List) {
      return data;
    } else if (data is Map<String, dynamic>) {
      var normal = await JsonLdProcessor.normalize(
          Map<String, dynamic>.from(data),
          options: JsonLdOptions(safeMode: true, documentLoader: loadDocument));
      //print(normal);
      return sha256.convert(utf8.encode(normal)).bytes;
    } else if (data is String) {
      return sha256.convert(utf8.encode(data)).bytes;
    } else {
      throw Exception('Unknown datatype for data');
    }
  }

  @override
  FutureOr<String> sign(
      {dynamic data,
      WalletStore? wallet,
      String? did,
      Map<String, dynamic>? jwk,
      bool detached = false,
      dynamic jwsHeader}) async {
    Map<String, dynamic> header;
    if (jwsHeader != null) {
      header = credentialToMap(jwsHeader);
      if (header['alg'] != 'EdDSA') {
        throw Exception('Unsupported Signature Algorithm ${header['alg']}');
      }
      if (header['crv'] != 'Ed25519') {
        throw Exception('Unsupported Curve ${header['crv']}');
      }
    } else {
      header = {'alg': 'EdDSA', 'crv': 'Ed25519'};
    }

    String encodedHeader = removePaddingFromBase64(
        base64UrlEncode(utf8.encode(jsonEncode(header))));
    String encodedPayload = removePaddingFromBase64(
        base64UrlEncode(utf8.encode(data is String ? data : jsonEncode(data))));
    String signingInput = '$encodedHeader.$encodedPayload';

    Map<String, dynamic>? key;

    if (wallet != null && did != null) {
      key = await wallet.getPrivateKeyForCredentialDidAsJwk(did);
      key ??= await wallet.getPrivateKeyForConnectionDidAsJwk(did);
      if (key == null) throw Exception('No key found in Wallet');
    } else if (jwk != null) {
      key = jwk;
    } else {
      throw Exception('No Private key given');
    }

    var privateKey =
        ed.newKeyFromSeed(base64Decode(addPaddingToBase64(key['d'])));

    var sig = ed.sign(privateKey, ascii.encode(signingInput));
    String encodedSig = removePaddingFromBase64(base64UrlEncode(sig));

    return detached
        ? '$encodedHeader..$encodedSig'
        : '$signingInput.$encodedSig';
  }

  @override
  Future<bool> verifyProof(proof, data, String did, {String? challenge}) async {
    //compare challenge
    if (challenge != null) {
      var containingChallenge = proof['challenge'];
      if (containingChallenge == null) {
        throw Exception('Expected challenge in this credential');
      }
      if (containingChallenge != challenge) {
        throw Exception(
            'challenge in credential do not match expected challenge');
      }
    }
    var proofValue = proof.remove('proofValue');
    proof['@context'] = ed25519ContextIri;

    List<int> hash = await _dataToHash(data);

    var proofHash = sha256
        .convert(utf8.encode(await JsonLdProcessor.normalize(proof,
            options:
                JsonLdOptions(safeMode: true, documentLoader: loadDocument))))
        .bytes;
    var hashToSign = proofHash + hash;
    // print(hashToSign);

    proof.remove('@context');
    proof['proofValue'] = proofValue;

    var ddo = await resolveDidDocument(did);
    ddo = ddo.resolveKeyIds().convertAllKeysToJwk();

    var verificationMethod = proof['verificationMethod'];
    dynamic usedJwk;
    for (var k in ddo.verificationMethod!) {
      if (k.id == verificationMethod) {
        usedJwk = k.publicKeyJwk!;
        break;
      }
    }

    if (usedJwk == null) {
      throw Exception(
          'Can\'t find public key for id $verificationMethod in did document');
    }

    if (usedJwk['crv'] != 'Ed25519') {
      throw Exception(
          'Wrong crv value ${usedJwk['crv']} for this signature suite (ed25519 needed)');
    }

    var decodedKey = base64Decode(addPaddingToBase64(usedJwk['x']));

    return ed.verify(ed.PublicKey(decodedKey), Uint8List.fromList(hashToSign),
        base58BitcoinDecode(proofValue.substring(1)));
  }

  @override
  FutureOr<bool> verify(String jws,
      {String? did, Map<String, dynamic>? jwk, dynamic data}) async {
    Map<String, dynamic> signingKey;
    if (did != null) {
      var ddo =
          (await resolveDidDocument(did)).resolveKeyIds().convertAllKeysToJwk();
      signingKey = ddo.verificationMethod!.first.publicKeyJwk!;
    } else if (jwk != null) {
      signingKey = jwk;
    } else {
      throw Exception('Either did or jwk must be given');
    }

    var splitted = jws.split('.');
    if (splitted.length != 3) throw Exception('maleformed jws');

    String encodedPayload;
    if (data != null) {
      encodedPayload = data is String
          ? removePaddingFromBase64(base64UrlEncode(utf8.encode(data)))
          : removePaddingFromBase64(
              base64UrlEncode(utf8.encode(jsonEncode(credentialToMap(data)))));
    } else {
      encodedPayload = splitted[1];
    }

    var signingInput = '${splitted[0]}.$encodedPayload';

    var publicKey =
        ed.PublicKey(base64Decode(addPaddingToBase64(signingKey['x'])));

    return ed.verify(publicKey, ascii.encode(signingInput),
        base64Decode(addPaddingToBase64(splitted[2])));
  }
}

class Es256Signer implements Signer {
  @override
  final String typeName = 'JsonWebSignature2020';
  @override
  final String algValue = 'ES256';
  @override
  final String crvValue = 'P-256';

  @override
  FutureOr<Map<String, dynamic>> buildProof(
      data, WalletStore wallet, String did,
      {String? challenge, String? domain, String? proofPurpose}) {
    // TODO: implement buildProof
    throw UnimplementedError();
  }

  @override
  FutureOr<String> sign(
      {dynamic data,
      WalletStore? wallet,
      String? did,
      Map<String, dynamic>? jwk,
      bool detached = false,
      dynamic jwsHeader}) async {
    Map<String, dynamic> header;
    if (jwsHeader != null) {
      header = credentialToMap(jwsHeader);
      if (header['alg'] != algValue) {
        throw Exception('Unsupported Signature Algorithm ${header['alg']}');
      }
      if (header['crv'] != crvValue) {
        throw Exception('Unsupported Curve ${header['crv']}');
      }
    } else {
      header = {'alg': algValue, 'crv': crvValue};
    }

    String encodedHeader = removePaddingFromBase64(
        base64UrlEncode(utf8.encode(jsonEncode(header))));
    String encodedPayload = removePaddingFromBase64(
        base64UrlEncode(utf8.encode(data is String ? data : jsonEncode(data))));
    String signingInput = '$encodedHeader.$encodedPayload';

    Map<String, dynamic>? key;
    if (wallet != null && did != null) {
      key = await wallet.getPrivateKeyForCredentialDidAsJwk(did);
      key ??= await wallet.getPrivateKeyForConnectionDidAsJwk(did);
      if (key == null) throw Exception('No key found in Wallet');
    } else if (jwk != null) {
      key = jwk;
    } else {
      throw Exception('No private key given');
    }

    var privateKey = EcPrivateKey(
        eccPrivateKey: web3_crypto
            .bytesToUnsignedInt(base64Decode(addPaddingToBase64(key['d']))),
        curve: curves.p256);

    var signer = privateKey.createSigner(algorithms.signing.ecdsa.sha256);
    var sig = signer.sign(ascii.encode(signingInput));

    String encodedSig = removePaddingFromBase64(base64UrlEncode(sig.data));

    return detached
        ? '$encodedHeader..$encodedSig'
        : '$signingInput.$encodedSig';
  }

  @override
  FutureOr<bool> verify(String jws,
      {String? did, Map<String, dynamic>? jwk, dynamic data}) async {
    Map<String, dynamic> signingKey;
    if (did != null) {
      var ddo =
          (await resolveDidDocument(did)).resolveKeyIds().convertAllKeysToJwk();
      signingKey = ddo.verificationMethod!.first.publicKeyJwk!;
    } else if (jwk != null) {
      signingKey = jwk;
    } else {
      throw Exception('Either did or jwk must be given');
    }

    var splitted = jws.split('.');
    if (splitted.length != 3) throw Exception('maleformed jws');

    String encodedPayload;
    if (data != null) {
      encodedPayload = data is String
          ? removePaddingFromBase64(base64UrlEncode(utf8.encode(data)))
          : removePaddingFromBase64(
              base64UrlEncode(utf8.encode(jsonEncode(credentialToMap(data)))));
    } else {
      encodedPayload = splitted[1];
    }

    var signingInput = '${splitted[0]}.$encodedPayload';

    var pubKey = EcPublicKey(
        xCoordinate: web3_crypto.bytesToUnsignedInt(
            base64Decode(addPaddingToBase64(signingKey['x']))),
        yCoordinate: web3_crypto.bytesToUnsignedInt(
            base64Decode(addPaddingToBase64(signingKey['y']))),
        curve: curves.p256);
    var verifier = pubKey.createVerifier(algorithms.signing.ecdsa.sha256);

    return verifier.verify(ascii.encode(signingInput),
        Signature(base64Decode(addPaddingToBase64(splitted[2]))));
  }

  @override
  FutureOr<bool> verifyProof(proof, data, String did, {String? challenge}) {
    // TODO: implement verifyProof
    throw UnimplementedError();
  }
}

class Es256k1Signer implements Signer {
  @override
  final String typeName = 'JsonWebSignature2020';
  @override
  final String algValue = 'ES256K';
  @override
  final String crvValue = 'secp256k1';

  @override
  FutureOr<Map<String, dynamic>> buildProof(
      data, WalletStore wallet, String did,
      {String? challenge, String? domain, String? proofPurpose}) {
    // TODO: implement buildProof
    throw UnimplementedError();
  }

  @override
  FutureOr<String> sign(
      {dynamic data,
      WalletStore? wallet,
      String? did,
      Map<String, dynamic>? jwk,
      bool detached = false,
      dynamic jwsHeader}) async {
    Map<String, dynamic> header;
    if (jwsHeader != null) {
      header = credentialToMap(jwsHeader);
      if (header['alg'] != algValue) {
        throw Exception('Unsupported Signature Algorithm ${header['alg']}');
      }
      if (header['crv'] != crvValue) {
        throw Exception('Unsupported Curve ${header['crv']}');
      }
    } else {
      header = {'alg': algValue, 'crv': crvValue};
    }

    String encodedHeader = removePaddingFromBase64(
        base64UrlEncode(utf8.encode(jsonEncode(header))));
    String encodedPayload = removePaddingFromBase64(
        base64UrlEncode(utf8.encode(data is String ? data : jsonEncode(data))));
    String signingInput = '$encodedHeader.$encodedPayload';

    Map<String, dynamic>? key;
    if (wallet != null && did != null) {
      key = await wallet.getPrivateKeyForCredentialDidAsJwk(did);
      key ??= await wallet.getPrivateKeyForConnectionDidAsJwk(did);
      if (key == null) throw Exception('No key found in Wallet');
    } else if (jwk != null) {
      key = jwk;
    } else {
      throw Exception('No private key given');
    }

    var privateKey = EcPrivateKey(
        eccPrivateKey: web3_crypto
            .bytesToUnsignedInt(base64Decode(addPaddingToBase64(key['d']))),
        curve: curves.p256k);

    var signer = privateKey.createSigner(algorithms.signing.ecdsa.sha256);
    var sig = signer.sign(ascii.encode(signingInput));

    String encodedSig = removePaddingFromBase64(base64UrlEncode(sig.data));

    return detached
        ? '$encodedHeader..$encodedSig'
        : '$signingInput.$encodedSig';
  }

  @override
  FutureOr<bool> verify(String jws,
      {String? did, Map<String, dynamic>? jwk, dynamic data}) async {
    Map<String, dynamic> signingKey;
    if (did != null) {
      var ddo =
          (await resolveDidDocument(did)).resolveKeyIds().convertAllKeysToJwk();
      signingKey = ddo.verificationMethod!.first.publicKeyJwk!;
    } else if (jwk != null) {
      signingKey = jwk;
    } else {
      throw Exception('Either did or jwk must be given');
    }

    var splitted = jws.split('.');
    if (splitted.length != 3) throw Exception('maleformed jws');

    String encodedPayload;
    if (data != null) {
      encodedPayload = data is String
          ? removePaddingFromBase64(base64UrlEncode(utf8.encode(data)))
          : removePaddingFromBase64(
              base64UrlEncode(utf8.encode(jsonEncode(credentialToMap(data)))));
    } else {
      encodedPayload = splitted[1];
    }

    var signingInput = '${splitted[0]}.$encodedPayload';

    var pubKey = EcPublicKey(
        xCoordinate: web3_crypto.bytesToUnsignedInt(
            base64Decode(addPaddingToBase64(signingKey['x']))),
        yCoordinate: web3_crypto.bytesToUnsignedInt(
            base64Decode(addPaddingToBase64(signingKey['y']))),
        curve: curves.p256k);
    var verifier = pubKey.createVerifier(algorithms.signing.ecdsa.sha256);

    return verifier.verify(ascii.encode(signingInput),
        Signature(base64Decode(addPaddingToBase64(splitted[2]))));
  }

  @override
  FutureOr<bool> verifyProof(proof, data, String did, {String? challenge}) {
    // TODO: implement verifyProof
    throw UnimplementedError();
  }
}
