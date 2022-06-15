import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:crypto/crypto.dart';
import 'package:dart_ssi/src/util/utils.dart';
import 'package:dart_web3/credentials.dart';
import 'package:dart_web3/crypto.dart' as web3Crypto;
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

import '../wallet/wallet_store.dart';
import 'credential_operations.dart';

abstract class Signer {
  late String typeName;
  FutureOr<Map<String, dynamic>> buildProof(
      dynamic data, WalletStore wallet, String did,
      {String? challenge, String? domain});
  FutureOr<Uint8List> sign(dynamic data, WalletStore wallet, String did,
      {String? challenge, String? domain});
  bool verify(dynamic proof, dynamic data, String did, {String? challenge});
}

class EcdsaRecoverySignature extends Signer {
  final String typeName = 'EcdsaSecp256k1RecoverySignature2020';

  @override
  Future<Map<String, dynamic>> buildProof(data, WalletStore wallet, String did,
      {String? challenge, String? domain}) async {
    var proofOptions = {
      'type': typeName,
      'proofPurpose': 'assertionMethod',
      'verificationMethod': did,
      'created': DateTime.now().toUtc().toIso8601String()
    };
    if (domain != null) {
      proofOptions['domain'] = domain;
    }
    if (challenge != null) {
      proofOptions['challenge'] = challenge;
    }
    String pOptions = jsonEncode(proofOptions);

    List<int> hashToSign = _dataToHash(data);

    var pOptionsHash = sha256.convert(utf8.encode(pOptions)).bytes;
    var hash = sha256.convert(pOptionsHash + hashToSign).bytes;
    var privateKeyHex = await wallet.getPrivateKeyForCredentialDid(did);
    if (privateKeyHex == null)
      privateKeyHex = await wallet.getPrivateKeyForConnectionDid(did);
    if (privateKeyHex == null) throw Exception('Could not find a private key');
    var key = EthPrivateKey.fromHex(privateKeyHex);

    var sigArray = _buildSignatureArray(hash as Uint8List, key);
    while (sigArray.length != 65) {
      sigArray = _buildSignatureArray(hash, key);
    }

    var critical = new Map<String, dynamic>();
    critical['b64'] = false;
    proofOptions['jws'] = '${buildJwsHeader(alg: 'ES256K-R', extra: critical)}.'
        '.${base64UrlEncode(sigArray)}';

    return proofOptions;
  }

  List<int> _dataToHash(dynamic data) {
    if (data is Uint8List)
      return data.toList();
    else if (data is List<int>)
      return data;
    else if (data is Map<String, dynamic>) {
      return sha256.convert(utf8.encode(jsonEncode(data))).bytes;
    } else if (data is String) {
      return sha256.convert(utf8.encode(data)).bytes;
    } else {
      throw Exception('Unknown datatype for data');
    }
  }

  @override
  Uint8List sign(data, WalletStore wallet, String did,
      {String? challenge, String? domain}) {
    // TODO: implement sign
    throw UnimplementedError();
  }

  List<int> _buildSignatureArray(Uint8List hash, EthPrivateKey privateKey) {
    web3Crypto.MsgSignature signature =
        web3Crypto.sign(hash, privateKey.privateKey);
    List<int> rList = web3Crypto.unsignedIntToBytes(signature.r);
    if (rList.length < 32) {
      List<int> rPad = List.filled(32 - rList.length, 0);
      rList = rPad + rList;
    }
    List<int> sList = web3Crypto.unsignedIntToBytes(signature.s);
    if (sList.length < 32) {
      List<int> sPad = List.filled(32 - sList.length, 0);
      sList = sPad + sList;
    }
    List<int> sigArray = rList + sList + [signature.v - 27];
    return sigArray;
  }

  @override
  bool verify(proof, data, String did, {String? challenge}) {
    //compare challenge
    if (challenge != null) {
      var containingChallenge = proof['challenge'];
      if (containingChallenge == null)
        throw Exception('Expected challenge in this credential');
      if (containingChallenge != challenge)
        throw Exception('a challenge do not match expected challenge');
    }

    //verify signature
    var signature = _getSignatureFromJws(proof['jws']);

    List<int> hash = _dataToHash(data);

    var jws = proof.remove('jws');
    var proofHash = sha256.convert(utf8.encode(jsonEncode(proof))).bytes;
    var hashToSign = sha256.convert(proofHash + hash).bytes;

    proof['jws'] = jws;

    var pubKey = web3Crypto.ecRecover(hashToSign as Uint8List, signature);

    var givenAddress = EthereumAddress.fromHex(did.split(':').last);

    return EthereumAddress.fromPublicKey(pubKey).hexEip55 ==
        givenAddress.hexEip55;
  }

  web3Crypto.MsgSignature _getSignatureFromJws(String jws) {
    var splitJws = jws.split('.');
    Map<String, dynamic> header =
        jsonDecode(utf8.decode(base64Decode(addPaddingToBase64(splitJws[0]))));
    if (header['alg'] != 'ES256K-R')
      throw Exception('Unsupported signature Algorithm ${header['alg']}');
    var sigArray = base64Decode(addPaddingToBase64(splitJws[2]));
    if (sigArray.length != 65) throw Exception('wrong signature-length');
    return new web3Crypto.MsgSignature(
        web3Crypto.bytesToUnsignedInt(sigArray.sublist(0, 32)),
        web3Crypto.bytesToUnsignedInt(sigArray.sublist(32, 64)),
        sigArray[64] + 27);
  }
}

class EdDsaSigner extends Signer {
  final String typeName = 'Ed25519Signature2020';
  @override
  FutureOr<Map<String, dynamic>> buildProof(
      data, WalletStore wallet, String did,
      {String? challenge, String? domain}) async {
    var proofOptions = {
      'type': typeName,
      'proofPurpose': 'assertionMethod',
      'verificationMethod': did,
      'created': DateTime.now().toUtc().toIso8601String()
    };
    if (domain != null) {
      proofOptions['domain'] = domain;
    }
    if (challenge != null) {
      proofOptions['challenge'] = challenge;
    }
    String pOptions = jsonEncode(proofOptions);

    List<int> hashToSign = _dataToHash(data);

    var pOptionsHash = sha256.convert(utf8.encode(pOptions)).bytes;
    var hash = sha256.convert(pOptionsHash + hashToSign).bytes;

    var privateKey = await wallet.getPrivateKeyForCredentialDid(did);
    if (privateKey == null)
      privateKey = await wallet.getPrivateKeyForConnectionDid(did);
    if (privateKey == null) throw Exception('Could not find a private key');
    var signature = ed.sign(
        ed.PrivateKey(web3Crypto.hexToBytes(privateKey).toList()),
        Uint8List.fromList(hash));

    proofOptions['proofValue'] = 'z${base58BitcoinEncode(signature)}';

    return proofOptions;
  }

  List<int> _dataToHash(dynamic data) {
    if (data is Uint8List)
      return data;
    else if (data is Map<String, dynamic>) {
      return sha256.convert(utf8.encode(jsonEncode(data))).bytes;
    } else if (data is String) {
      return sha256.convert(utf8.encode(data)).bytes;
    } else {
      throw Exception('Unknown datatype for data');
    }
  }

  @override
  FutureOr<Uint8List> sign(data, WalletStore wallet, String did,
      {String? challenge, String? domain}) {
    // TODO: implement sign
    throw UnimplementedError();
  }

  @override
  bool verify(proof, data, String did, {String? challenge}) {
    //compare challenge
    if (challenge != null) {
      var containingChallenge = proof['challenge'];
      if (containingChallenge == null)
        throw Exception('Expected challenge in this credential');
      if (containingChallenge != challenge)
        throw Exception(
            'challenge in credential do not match expected challenge');
    }
    var proofValue = proof.remove('proofValue');

    List<int> hash = _dataToHash(data);

    var proofHash = sha256.convert(utf8.encode(jsonEncode(proof))).bytes;
    var hashToSign = sha256.convert(proofHash + hash).bytes;

    proof['proofValue'] = proofValue;

    var encodedKey = did.split(':')[2];
    var base58DecodedKey = base58BitcoinDecode(encodedKey.substring(1));
    return ed.verify(
        ed.PublicKey(base58DecodedKey.sublist(2)),
        Uint8List.fromList(hashToSign),
        base58BitcoinDecode(proofValue.substring(1)));
  }
}
