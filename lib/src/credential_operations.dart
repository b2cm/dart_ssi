import 'dart:convert';

import 'package:ethereum_util/ethereum_util.dart' as util;
import 'package:meta/meta.dart';
import 'package:web3dart/credentials.dart';
import 'package:web3dart/crypto.dart';

import 'wallet_store.dart';

bool verifyPresentation(String presentation) {
  return true;
}

String buildPresentation() {
  return '';
}

String signCredential(WalletStore wallet, String credential,
    {String proofOptions}) {
  String issuerDid = getIssuerDidFromCredential(credential);
  if (issuerDid == null) {
    // TODO search for better Exception-Type
    throw new Exception('Could not examine IssuerDID');
  }

  String pOptions;
  if (proofOptions == null) {
    pOptions = buildProofOptions(verificationMethod: issuerDid);
  } else {
    pOptions = proofOptions;
  }

  var pOptionsHash = util.sha256(pOptions);
  var credHash = util.sha256(credential);
  var hashToSign = util.sha256(pOptionsHash + credHash);

  var privKeyHex = wallet.getPrivateKeyToDid(issuerDid);
  var key = EthPrivateKey.fromHex(privKeyHex);
  MsgSignature signature = sign(hashToSign, key.privateKey);
  var sigArray = intToBytes(signature.r) +
      intToBytes(signature.s) +
      util.intToBuffer(signature.v - 27);

  Map<String, dynamic> credMap = jsonDecode(credential);
  Map<String, dynamic> optionsMap = jsonDecode(pOptions);

  var critical = new Map<String, dynamic>();
  critical.putIfAbsent('b64', () => false);
  optionsMap.putIfAbsent(
      'jws',
      () => '${buildJwsHeader(alg: 'ES256K-R', extra: critical)}.'
          '.${base64Encode(sigArray)}');

  credMap.putIfAbsent('proof', () => optionsMap);
  return jsonEncode(credMap);
}

bool verifyCredential(String credential) {
  Map<String, dynamic> credMap = jsonDecode(credential);
  if (!credMap.containsKey('proof')) {
    throw Exception('no proof section found');
  }

  Map<String, dynamic> proof = credMap['proof'];
  var signature = getSignatureFromJws(proof['jws']);

  credMap.remove('proof');
  proof.remove('jws');

  var credHash = util.sha256(jsonEncode(credMap));
  var proofHash = util.sha256(jsonEncode(proof));

  var hashToSign = util.sha256(proofHash + credHash);

  var pubKey = util.recoverPublicKeyFromSignature(signature, hashToSign);
  var recoverdDid =
      'did:ethr:${EthereumAddress.fromPublicKey(pubKey).hexEip55.substring(2)}';
  var issuerDid = getIssuerDidFromCredential(credential);
  return recoverdDid == issuerDid;
}

String buildProofOptions(
    {@required String verificationMethod, String domain, String nonce}) {
  Map<String, dynamic> jsonObject = new Map();
  jsonObject.putIfAbsent('type', () => 'EcdsaSecp256k1RecoverySignature2020');
  jsonObject.putIfAbsent('proofPurpose', () => 'assertionMethod');
  jsonObject.putIfAbsent('verificationMethod', () => verificationMethod);
  jsonObject.putIfAbsent('created', () => DateTime.now().toIso8601String());

  if (domain != null) {
    jsonObject.putIfAbsent('domain', () => domain);
  }

  if (nonce != null) {
    jsonObject.putIfAbsent('nonce', () => nonce);
  }

  return json.encode(jsonObject);
}

String buildJwsHeader(
    {@required String alg,
    String jku,
    Map<String, dynamic> jwk,
    String kid,
    String x5u,
    List<String> x5c,
    String x5t,
    String x5tS256,
    String typ,
    Map<String, dynamic> extra}) {
  Map<String, dynamic> jsonObject = new Map();

  jsonObject.putIfAbsent('alg', () => alg);

  if (jku != null) {
    jsonObject.putIfAbsent('jku', () => jku);
  }

  if (jwk != null) {
    jsonObject.putIfAbsent('jwk', () => jwk);
  }

  if (kid != null) {
    jsonObject.putIfAbsent('kid', () => kid);
  }

  if (x5u != null) {
    jsonObject.putIfAbsent('x5u', () => x5u);
  }

  if (x5c != null) {
    jsonObject.putIfAbsent('x5c', () => x5c);
  }

  if (x5t != null) {
    jsonObject.putIfAbsent('x5t', () => x5t);
  }

  if (x5tS256 != null) {
    jsonObject.putIfAbsent('x5t#S256', () => x5tS256);
  }

  if (typ != null) {
    jsonObject.putIfAbsent('typ', () => typ);
  }

  if (extra != null) {
    jsonObject.addAll(extra);
    var keyList = extra.keys.toList();
    jsonObject.putIfAbsent('crit', () => keyList);
  }

  var jsonString = jsonEncode(jsonObject);
  return base64Encode(utf8.encode(jsonString));
}

String getIssuerDidFromCredential(String jsonCredential) {
  Map<String, dynamic> credentialMap = jsonDecode(jsonCredential);

  if (!credentialMap.containsKey('issuer'))
    return null;
  else {
    var issuer = credentialMap['issuer'];
    if (issuer is String)
      return issuer;
    else {
      if (!(issuer is Map))
        return null;
      else {
        return issuer['id'];
      }
    }
  }
}

util.ECDSASignature getSignatureFromJws(String jws) {
  var splitJws = jws.split('.');
  var sigArray = base64Decode(splitJws[2]);
  if (sigArray.length != 65) throw Exception('wrong signature');
  return new util.ECDSASignature(bytesToInt(sigArray.sublist(0, 32)),
      bytesToInt(sigArray.sublist(32, 64)), sigArray[64] + 27);
}
