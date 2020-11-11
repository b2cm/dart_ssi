import 'dart:convert';
import 'dart:typed_data';

import 'package:ethereum_util/ethereum_util.dart' as util;
import 'package:json_schema/json_schema.dart';
import 'package:meta/meta.dart';
import 'package:uuid/uuid.dart';
import 'package:web3dart/credentials.dart';
import 'package:web3dart/crypto.dart';

import 'wallet_store.dart';

final hashedAttributeSchema = {
  "type": "object",
  "required": ["hash"],
  "properties": {
    "value": {
      "type": ["number", "string", "boolean"]
    },
    "salt": {"type": "string"},
    "hash": {"type": "string"}
  },
  "additionalProperties": false
};

final mapOfHashedAttributesSchema = {
  'type': 'object',
  'properties': {r'^.*$': hashedAttributeSchema}
};

bool verifyPresentation(dynamic presentation) {
  var presentationMap = _credentialToMap(presentation);
  var proofs = presentationMap['proof'] as List;
  presentationMap.remove('proof');
  var presentationHash = util.sha256(jsonEncode(presentationMap));

  var credentials = presentationMap['verifiableCredential'] as List;
  var holderDids = new List<String>();
  credentials.forEach((element) {
    if (!verifyCredential(element))
      throw Exception('Credential $element cold not been verified');
    else
      holderDids.add(getHolderDidFromCredential(element));
  });

  proofs.forEach((element) {
    var verifMeth = element['verificationMethod'];
    if (holderDids.contains(verifMeth)) holderDids.remove(verifMeth);
    if (!_verifyProof(element, presentationHash, verifMeth))
      throw Exception('Proof for $verifMeth could not been verified');
  });

  if (holderDids.isNotEmpty) throw Exception('There are dids without a proof');
  return true;
}

String buildPresentation(List<dynamic> credentials, WalletStore wallet) {
  var credMapList = new List<Map<String, dynamic>>();
  var holderDids = new List<String>();
  credentials.forEach((element) {
    var credMap = _credentialToMap(element);
    credMapList.add(credMap);
    holderDids.add(getHolderDidFromCredential(credMap));
  });
  var presentation = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://identity.hs-mittweida.de/credentials/context'
    ],
    'type': ['VerifiablePresentation'],
    'verifiableCredential': credMapList
  };
  var presentationHash = util.sha256(jsonEncode(presentation));
  var proofList = new List<Map<String, dynamic>>();
  holderDids.forEach((element) {
    var proof = _buildProof(presentationHash, element, wallet);
    proofList.add(proof);
  });
  presentation.putIfAbsent('proof', () => proofList);
  return jsonEncode(presentation);
}

String buildHashedValueCredential(dynamic credential) {
  Map<String, dynamic> credMap = _credentialToMap(credential);
  Map<String, dynamic> finalCred = new Map();

  if (credMap.containsKey('credentialSubject')) {
    credMap = credMap['credentialSubject'];
  }

  credMap.forEach((key, value) {
    if (value is String || value is num || value is bool) {
      finalCred[key] = _hashStringOrNum(value);
    } else if (value is List) {
      List<Map<String, dynamic>> newValue = new List();
      value.forEach((element) {
        if (element is String || element is num || element is bool)
          newValue.add(_hashStringOrNum(element));
        else if (element is Map<String, dynamic>) {
          newValue.add(jsonDecode(buildHashedValueCredential(element)));
        } else
          throw Exception('unknown type with key $key');
      });
      finalCred[key] = newValue;
    } else if (value is Map<String, dynamic>) {
      finalCred[key] = jsonDecode(buildHashedValueCredential(value));
    } else {
      throw Exception('unknown datatype  with key $key');
    }
  });

  return jsonEncode(finalCred);
}

Map<String, dynamic> _hashStringOrNum(dynamic value) {
  var uuid = Uuid();
  Map<String, dynamic> hashed = new Map();
  var salt = uuid.v4();
  var hash = util.bufferToHex(util.keccak256(salt + value.toString()));
  hashed.putIfAbsent('value', () => value);
  hashed.putIfAbsent('salt', () => salt);
  hashed.putIfAbsent('hash', () => hash);
  return hashed;
}

String buildCredentialHash(dynamic credential) {
  var credMap = _credentialToMap(credential);
  String hashes = '';
  credMap.forEach((key, value) {
    if (value is List) {
      String listHash = '';
      value.forEach((element) {
        if (element is Map<String, dynamic> &&
            JsonSchema.createSchema(hashedAttributeSchema).validate(element)) {
          listHash += (element['hash'] as String..substring(2));
        } else {
          throw Exception('unknown type  with key $key');
        }
        hashes += util.bufferToHex(util.keccak256(hashes)).substring(2);
      });
    } else if (value is Map<String, dynamic> &&
        JsonSchema.createSchema(hashedAttributeSchema).validate(value)) {
      hashes += (value['hash'] as String..substring(2));
    } else if (value is Map<String, dynamic> &&
        JsonSchema.createSchema(mapOfHashedAttributesSchema).validate(value)) {
      hashes += buildCredentialHash(value);
    } else {
      throw Exception('unknown type  with key $key');
    }
  });

  return util.bufferToHex(util.keccak256(hashes));
}

String buildW3cCredentialToPlaintextCred(
    dynamic credential, String holderDid, String issuerDid) {
  var plaintextHash = buildCredentialHash(credential);
  var w3cCred = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://identity.hs-mittweida.de/credentials/context'
    ],
    'type': ['VerifiableCredential'],
    'credentialSubject': {'id': holderDid, 'claimHash': plaintextHash},
    'issuer': issuerDid,
    'issuanceDate': DateTime.now().toUtc().toIso8601String()
  };

  return jsonEncode(w3cCred);
}

Map<String, dynamic> _buildProof(
    Uint8List hashToSign, String didToSignWith, WalletStore wallet,
    {String proofOptions}) {
  String pOptions;
  if (proofOptions == null) {
    pOptions = buildProofOptions(verificationMethod: didToSignWith);
  } else {
    pOptions = proofOptions;
  }

  var pOptionsHash = util.sha256(pOptions);
  var hash = util.sha256(pOptionsHash + hashToSign);
  var privKeyHex = wallet.getPrivateKeyToDid(didToSignWith);
  var key = EthPrivateKey.fromHex(privKeyHex);
  MsgSignature signature = sign(hash, key.privateKey);
  var sigArray = intToBytes(signature.r) +
      intToBytes(signature.s) +
      util.intToBuffer(signature.v - 27);

  Map<String, dynamic> optionsMap = jsonDecode(pOptions);

  var critical = new Map<String, dynamic>();
  critical.putIfAbsent('b64', () => false);
  optionsMap.putIfAbsent(
      'jws',
      () => '${buildJwsHeader(alg: 'ES256K-R', extra: critical)}.'
          '.${base64Encode(sigArray)}');

  return optionsMap;
}

String signCredential(WalletStore wallet, String credential,
    {String proofOptions}) {
  String issuerDid = getIssuerDidFromCredential(credential);
  if (issuerDid == null) {
    // TODO search for better Exception-Type
    throw new Exception('Could not examine IssuerDID');
  }

  var credHash = util.sha256(credential);
  var proof;
  if (proofOptions == null) {
    proof = _buildProof(credHash, issuerDid, wallet);
  } else {
    proof =
        _buildProof(credHash, issuerDid, wallet, proofOptions: proofOptions);
  }
  Map<String, dynamic> credMap = jsonDecode(credential);
  credMap.putIfAbsent('proof', () => proof);
  return jsonEncode(credMap);
}

bool _verifyProof(Map<String, dynamic> proof, Uint8List hash, String did) {
  var signature = getSignatureFromJws(proof['jws']);

  proof.remove('jws');

  var proofHash = util.sha256(jsonEncode(proof));
  var hashToSign = util.sha256(proofHash + hash);

  var pubKey = util.recoverPublicKeyFromSignature(signature, hashToSign);
  var recoverdDid =
      'did:ethr:${EthereumAddress.fromPublicKey(pubKey).hexEip55.substring(2)}';

  return recoverdDid == did;
}

bool verifyCredential(dynamic credential) {
  Map<String, dynamic> credMap = _credentialToMap(credential);
  if (!credMap.containsKey('proof')) {
    throw Exception('no proof section found');
  }

  Map<String, dynamic> proof = credMap['proof'];
  credMap.remove('proof');
  var credHash = util.sha256(jsonEncode(credMap));
  var issuerDid = getIssuerDidFromCredential(credential);
  return _verifyProof(proof, credHash, issuerDid);
}

String buildProofOptions(
    {@required String verificationMethod, String domain, String nonce}) {
  Map<String, dynamic> jsonObject = new Map();
  jsonObject.putIfAbsent('type', () => 'EcdsaSecp256k1RecoverySignature2020');
  jsonObject.putIfAbsent('proofPurpose', () => 'assertionMethod');
  jsonObject.putIfAbsent('verificationMethod', () => verificationMethod);
  jsonObject.putIfAbsent(
      'created', () => DateTime.now().toUtc().toIso8601String());

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

String getIssuerDidFromCredential(dynamic credential) {
  var credentialMap = _credentialToMap(credential);

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

String getHolderDidFromCredential(dynamic credential) {
  var credMap = _credentialToMap(credential);
  if (credMap.containsKey('credentialSubject'))
    return credMap['credentialSubject']['id'];
  else
    return credMap['id'];
}

util.ECDSASignature getSignatureFromJws(String jws) {
  var splitJws = jws.split('.');
  var sigArray = base64Decode(splitJws[2]);
  if (sigArray.length != 65) throw Exception('wrong signature');
  return new util.ECDSASignature(bytesToInt(sigArray.sublist(0, 32)),
      bytesToInt(sigArray.sublist(32, 64)), sigArray[64] + 27);
}

Map<String, dynamic> _credentialToMap(dynamic credential) {
  if (credential is String)
    return jsonDecode(credential);
  else if (credential is Map<String, dynamic>)
    return credential;
  else
    throw Exception('unknown type');
}
