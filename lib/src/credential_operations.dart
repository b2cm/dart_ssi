import 'dart:convert';
import 'dart:typed_data';

import 'package:ethereum_util/ethereum_util.dart' as util;
import 'package:flutter_ssi_wallet/flutter_ssi_wallet.dart';
import 'package:json_schema/json_schema.dart';
import 'package:meta/meta.dart';
import 'package:uuid/uuid.dart';
import 'package:web3dart/credentials.dart';
import 'package:web3dart/crypto.dart';

import 'wallet_store.dart';

final _hashedAttributeSchemaMap = {
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
final _hashedAttributeSchema =
    JsonSchema.createSchema(_hashedAttributeSchemaMap);

final _hashedAttributeSchemaStrict = JsonSchema.createSchema({
  "type": "object",
  "required": ["hash", "salt", "value"],
  "properties": {
    "value": {
      "type": ["number", "string", "boolean"]
    },
    "salt": {"type": "string"},
    "hash": {"type": "string"}
  },
  "additionalProperties": false
});

final _mapOfHashedAttributesSchema = JsonSchema.createSchema({
  'type': 'object',
  'properties': {r'^.*$': _hashedAttributeSchemaMap}
});

/// Builds a json-Object where every Attribute gets a value, salt and hash from json-Object [credential].
///
/// E.g.
/// ```
/// {
///   "name" : "Max",
///   "age" : 20
/// }
/// ```
/// becomes to
///```
///{
/// "name":
/// {
///   "value":"Max",
///   "salt":"dc0931a0-60c6-4bc8-a27d-b3fd13e62c63",
///   "hash":"0xd8925653ed000200d2b491bcabe2ea69f378abb91f056993a6d3e3b28ad4ccc4"
///  },
///  "age":
///   {
///   "value":20,
///   "salt":"3e9bacd3-aa74-42c1-9895-e490e3931a73",
///   "hash":"0x43bde6fcd11015c6a996206dadd25e149d131c69a7249280bae723c6bad53888"
///  }
/// }
/// ```
/// where salt is a Version 4 UUID and hash is the keccak256-hash of salt + value (concatenation).
/// [credential] could be a string or Map<String, dynamic> representing a valid json-Object.
String buildPlaintextCredential(dynamic credential) {
  Map<String, dynamic> credMap = _credentialToMap(credential);
  Map<String, dynamic> finalCred = new Map();

  if (credMap.containsKey('credentialSubject')) {
    credMap = credMap['credentialSubject'];
  }
  if (credMap.containsKey('@context')) {
    finalCred['@context'] = credMap['@context'];
    credMap.remove('@context');
  }

  credMap.forEach((key, value) {
    if (key == 'type' || key == '@type') {
      finalCred[key] = value;
    } else if (value is String || value is num || value is bool) {
      finalCred[key] = _hashStringOrNum(value);
    } else if (value is List) {
      List<Map<String, dynamic>> newValue = new List();
      value.forEach((element) {
        if (element is String || element is num || element is bool)
          newValue.add(_hashStringOrNum(element));
        else if (element is Map<String, dynamic>) {
          newValue.add(jsonDecode(buildPlaintextCredential(element)));
        } else
          throw Exception('unknown type with key $key');
      });
      finalCred[key] = newValue;
    } else if (value is Map<String, dynamic>) {
      finalCred[key] = jsonDecode(buildPlaintextCredential(value));
    } else {
      throw Exception('unknown datatype  with key $key');
    }
  });

  return jsonEncode(finalCred);
}

///
/// Collects all hashes from a Plaintext-Credential, concatenates them and re-hash them with keccak256.
///
String buildCredentialHash(dynamic credential) {
  var credMap = _credentialToMap(credential);
  String hashes = '';
  credMap.forEach((key, value) {
    if (!(key == '@context' || key == 'type' || key == '@type')) {
      if (value is List) {
        String listHash = '';
        value.forEach((element) {
          if (element is Map<String, dynamic> &&
              _hashedAttributeSchema.validate(element)) {
            listHash += (element['hash'] as String..substring(2));
          } else if (element is Map<String, dynamic> &&
              _mapOfHashedAttributesSchema.validate(element)) {
            listHash += buildCredentialHash(element);
          } else {
            throw Exception('unknown type  with key $key');
          }
          hashes += util.bufferToHex(util.keccak256(hashes)).substring(2);
        });
      } else if (value is Map<String, dynamic> &&
          _hashedAttributeSchema.validate(value)) {
        hashes += (value['hash'] as String..substring(2));
      } else if (value is Map<String, dynamic> &&
          _mapOfHashedAttributesSchema.validate(value)) {
        hashes += buildCredentialHash(value);
      } else {
        throw Exception('unknown type  with key $key');
      }
    }
  });

  return util.bufferToHex(util.keccak256(hashes));
}

/// Builds a Credential conform to W3C-Specification containing a single hash
/// for plaintext-Credential [credential].
String buildW3cCredentialSingleHash(
    dynamic credential, String holderDid, String issuerDid,
    {dynamic type, dynamic context}) {
  var plaintextHash = buildCredentialHash(credential);

  var credTypes = new List<String>();
  credTypes.add('VerifiableCredential');
  if (type != null) {
    if (type is String && type != 'VerifiableCredential')
      credTypes.add(type);
    else if (type is List<String>) {
      if (type.contains('VerifiableCredential')) {
        type.remove('VerifiableCredential');
      }
      credTypes += type;
    } else
      throw Exception('type has unknown datatype');
  }

  var credContext = new List<String>();
  credContext.add('https://www.w3.org/2018/credentials/v1');
  if (context != null) {
    if (context is String &&
        context != 'https://www.w3.org/2018/credentials/v1')
      credContext.add(context);
    else if (context is List<String>) {
      if (context.contains('https://www.w3.org/2018/credentials/v1')) {
        context.remove('https://www.w3.org/2018/credentials/v1');
      }
      credContext += context;
    } else
      throw Exception('type has unknown datatype');
  }

  var w3cCred = {
    '@context': credContext,
    'type': credTypes,
    'credentialSubject': {'id': holderDid, 'claimHash': plaintextHash},
    'issuer': issuerDid,
    'issuanceDate': DateTime.now().toUtc().toIso8601String()
  };

  return jsonEncode(w3cCred);
}

/// Builds a credential conform to W3C-Standard, which includes all hashes a
/// plaintext-credential [credential] contains.
String buildW3cCredentialwithHashes(
    dynamic credential, String holderDid, String issuerDid,
    {dynamic type, dynamic context, String revocationRegistryAddress}) {
  var hashCred = _collectHashes(credential, id: holderDid);

  var credTypes = new List<String>();
  credTypes.add('VerifiableCredential');
  if (type != null) {
    if (type is String) {
      if (type != 'VerifiableCredential') credTypes.add(type);
    } else if (type is List<String>) {
      if (type.contains('VerifiableCredential')) {
        type.remove('VerifiableCredential');
      }
      credTypes += type;
    } else
      throw Exception('type has unknown datatype');
  }

  var credContext = new List<String>();
  credContext.add('https://www.w3.org/2018/credentials/v1');
  if (context != null) {
    if (context is String) {
      if (context != 'https://www.w3.org/2018/credentials/v1')
        credContext.add(context);
    } else if (context is List<String>) {
      if (context.contains('https://www.w3.org/2018/credentials/v1')) {
        context.remove('https://www.w3.org/2018/credentials/v1');
      }
      credContext += context;
    } else
      throw Exception('type has unknown datatype');
  }
  // adding context of Plaintext-credential
  var plaintextCredMap = _credentialToMap(credential);
  if (plaintextCredMap.containsKey('@context')) {
    var context = plaintextCredMap['@context'];
    if (context is List) {
      context.forEach((element) {
        if (!credContext.contains(element)) {
          credContext.add(element);
        }
      });
    } else if (context is String) {
      if (!credContext.contains(context)) credContext.add(context);
    } else
      throw Exception('@context has unsupported type');
  }

  var w3cCred = {
    '@context': credContext,
    'type': credTypes,
    'credentialSubject': jsonDecode(hashCred),
    'issuer': issuerDid,
    'issuanceDate': DateTime.now().toUtc().toIso8601String()
  };

  if (revocationRegistryAddress != null) {
    var credStatus = {
      'id': revocationRegistryAddress,
      'type': 'EthereumRevocationList'
    };
    w3cCred['credentialStatus'] = credStatus;
  }

  return jsonEncode(w3cCred);
}

/// Checks weather a W3C-Credential containing all attribute hashes belongs to a Plaintext Credential or not.
bool compareW3cCredentialAndPlaintext(dynamic w3cCred, dynamic plaintext) {
  var w3cMap = _credentialToMap(w3cCred);
  var plainMap = _credentialToMap(plaintext);
  if (w3cMap.containsKey('credentialSubject'))
    w3cMap = w3cMap['credentialSubject'];

  return _checkHashes(w3cMap, plainMap);
}

/// Signs a W3C-Standard conform [credential] with the private key for issuer-did in the credential.
String signCredential(WalletStore wallet, dynamic credential) {
  credential = _credentialToMap(credential);
  String issuerDid = getIssuerDidFromCredential(credential);
  if (issuerDid == null) {
    throw new Exception('Could not examine IssuerDID');
  }

  var credHash = util.sha256(jsonEncode(credential));
  var proof = _buildProof(credHash, issuerDid, wallet);

  credential['proof'] = proof;
  return jsonEncode(credential);
}

/// Verifies the signature for the given [credential].
Future<bool> verifyCredential(
    dynamic credential, Erc1056 erc1056, String rpcUrl) async {
  Map<String, dynamic> credMap = _credentialToMap(credential);
  if (!credMap.containsKey('proof')) {
    throw Exception('no proof section found');
  }

  if (credMap.containsKey('credentialStatus')) {
    var credStatus = credMap['credentialStatus'];
    if (credStatus['type'] != 'EthereumRevocationList')
      throw Exception('Unknown Status-method : ${credStatus['type']}');
    var revRegistry =
        RevocationRegistry(rpcUrl, contractAddress: credStatus['id']);
    var revoked =
        await revRegistry.isRevoked(getHolderDidFromCredential(credMap));
    if (revoked) throw Exception('Credential was revoked');
  }

  Map<String, dynamic> proof = credMap['proof'];
  credMap.remove('proof');
  var credHash = util.sha256(jsonEncode(credMap));
  var issuerDid = getIssuerDidFromCredential(credential);
  var owner = await erc1056.identityOwner(issuerDid);
  return _verifyProof(proof, credHash, owner);
}

/// Builds a presentation for [credentials].
String buildPresentation(
    List<dynamic> credentials, WalletStore wallet, String challenge) {
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
    var proof = _buildProof(presentationHash, element, wallet,
        proofOptions: _buildProofOptions(
            verificationMethod: element, challenge: challenge));
    proofList.add(proof);
  });
  presentation.putIfAbsent('proof', () => proofList);
  return jsonEncode(presentation);
}

/// Verifies the [presentation].
///
/// It uses erc1056 to look up the current owner of the dids a proof is given in [presentation].
Future<bool> verifyPresentation(dynamic presentation, Erc1056 erc1056,
    String challenge, String rpcUrl) async {
  var presentationMap = _credentialToMap(presentation);
  var proofs = presentationMap['proof'] as List;
  presentationMap.remove('proof');
  var presentationHash = util.sha256(jsonEncode(presentationMap));

  var credentials = presentationMap['verifiableCredential'] as List;
  var holderDids = new List<String>();
  await Future.forEach(credentials, (element) async {
    if (!(await verifyCredential(element, erc1056, rpcUrl)))
      throw Exception('Credential $element cold not been verified');
    else {
      var did = getHolderDidFromCredential(element);
      var currentAddress = await erc1056.identityOwner(did);
      holderDids.add(currentAddress);
    }
  });

  proofs.forEach((element) {
    var verifMeth = element['verificationMethod'];
    var includedNonce = element['challenge'];
    if (includedNonce != challenge) throw Exception('Challenge does not match');
    if (holderDids.contains(verifMeth)) holderDids.remove(verifMeth);
    if (!_verifyProof(element, presentationHash, verifMeth))
      throw Exception('Proof for $verifMeth could not been verified');
  });

  if (holderDids.isNotEmpty) throw Exception('There are dids without a proof');
  return true;
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

/// Collects the did of the issuer of a [credential].
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

/// Collects the did of the Holder of [credential].
String getHolderDidFromCredential(dynamic credential) {
  var credMap = _credentialToMap(credential);
  if (credMap.containsKey('credentialSubject')) {
    if (credMap['credentialSubject'].containsKey('id'))
      return credMap['credentialSubject']['id'];
    else
      return null;
  } else if (credMap.containsKey('id'))
    return credMap['id'];
  else
    return null;
}

Map<String, dynamic> _credentialToMap(dynamic credential) {
  if (credential is String)
    return jsonDecode(credential);
  else if (credential is Map<String, dynamic>)
    return credential;
  else
    throw Exception('unknown type for $credential');
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

String _collectHashes(dynamic credential, {String id}) {
  var credMap = _credentialToMap(credential);
  Map<String, dynamic> hashCred = new Map();
  if (id != null) hashCred['id'] = id;
  credMap.forEach((key, value) {
    if (key != '@context') {
      if (key == 'type' || key == '@type')
        hashCred[key] = value;
      else if (value is List) {
        var hashList = new List<dynamic>();
        value.forEach((element) {
          if (element is Map<String, dynamic> &&
              _hashedAttributeSchema.validate(element)) {
            hashList.add(element['hash']);
          } else if (element is Map<String, dynamic> &&
              _mapOfHashedAttributesSchema.validate(element)) {
            hashList.add(jsonDecode(_collectHashes(element)));
          } else {
            throw Exception('unknown type  with key $key');
          }
          hashCred[key] = hashList;
        });
      } else if (value is Map<String, dynamic> &&
          _hashedAttributeSchema.validate(value)) {
        hashCred[key] = value['hash'];
      } else if (value is Map<String, dynamic> &&
          _mapOfHashedAttributesSchema.validate(value)) {
        hashCred[key] = jsonDecode(_collectHashes(value));
      } else {
        throw Exception('unknown type  with key $key');
      }
    }
  });
  return jsonEncode(hashCred);
}

bool _checkHashes(Map<String, dynamic> w3c, Map<String, dynamic> plainHash) {
  plainHash.forEach((key, value) {
    if (!(key == '@context' || key == 'type' || key == '@type')) {
      if (value is String) {
        //Nothing was disclosed -> only compare hash
        if (w3c[key] != value) throw Exception('hashes do not match at $key');
      } else if (value is Map<String, dynamic>) {
        if (_hashedAttributeSchemaStrict.validate(value)) {
          //a disclosed value -> rehash and check
          var hash = util.bufferToHex(
              util.keccak256(value['salt'] + value['value'].toString()));
          if (hash != value['hash'])
            throw Exception(
                'Given hash and calculated hash do ot match at $key');
        } else if (_mapOfHashedAttributesSchema.validate(value) &&
            _mapOfHashedAttributesSchema.validate(w3c[key])) {
          // a new Object
          _checkHashes(w3c[key], value);
        } else if (value.length == 1 && value.containsKey('hash')) {
          // hash value was left in an object
          if (w3c[key] != value['hash'])
            throw Exception('hashes do not match at $key');
        } else
          throw Exception('malformed object with key $key');
      } else if (value is List) {
        List<dynamic> fromW3c = w3c[key];
        if (fromW3c.length != value.length)
          throw Exception('List length at $key do not match');
        for (int i = 0; i < value.length; i++) {
          if (value[i] is String) {
            //we found only strings -> nothing is disclosed
            if (value[i] != fromW3c[i])
              throw Exception(
                  'Hashes in List at $key do not match at index $i');
          } else if (value[i] is Map<String, dynamic> &&
              _hashedAttributeSchemaStrict.validate(value[i])) {
            // a disclosed value -> rehash and check
            var hash = util.bufferToHex(util
                .keccak256(value[i]['salt'] + value[i]['value'].toString()));
            if (hash != fromW3c[i])
              throw Exception(
                  'Calculated and given Hash in List at $key do not match at '
                  'index $i');
          } else if (value[i] is Map<String, dynamic> &&
              value[i].length == 1 &&
              value[i].containsKey('hash')) {
            if (fromW3c[i] != value[i]['hash'])
              throw Exception('hashes do not match at $key and index $i');
          } else if (value[i] is Map<String, dynamic> &&
              _mapOfHashedAttributesSchema.validate(value[i])) {
            _checkHashes(fromW3c[i], value[i]);
          } else
            throw Exception('unknown datatype at List $key and index $i');
        }
      } else
        throw Exception('unknown datatype with key $key');
    }
  });
  return true;
}

Map<String, dynamic> _buildProof(
    Uint8List hashToSign, String didToSignWith, WalletStore wallet,
    {dynamic proofOptions}) {
  String pOptions;
  if (proofOptions == null) {
    pOptions = _buildProofOptions(verificationMethod: didToSignWith);
  } else {
    if (!(proofOptions is String) || !(proofOptions is Map<String, dynamic>))
      throw Exception('Proof options have unsupported datatype');
    if (proofOptions is String)
      pOptions = proofOptions;
    else
      pOptions = jsonEncode(proofOptions);
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
  critical['b64'] = false;
  optionsMap['jws'] = '${buildJwsHeader(alg: 'ES256K-R', extra: critical)}.'
      '.${base64Encode(sigArray)}';

  return optionsMap;
}

bool _verifyProof(Map<String, dynamic> proof, Uint8List hash, String did) {
  var signature = _getSignatureFromJws(proof['jws']);

  proof.remove('jws');

  var proofHash = util.sha256(jsonEncode(proof));
  var hashToSign = util.sha256(proofHash + hash);

  var pubKey = util.recoverPublicKeyFromSignature(signature, hashToSign);
  var recoverdDid =
      'did:ethr:${EthereumAddress.fromPublicKey(pubKey).hexEip55}';
  return recoverdDid == did;
}

String _buildProofOptions(
    {@required String verificationMethod, String domain, String challenge}) {
  Map<String, dynamic> jsonObject = new Map();
  jsonObject.putIfAbsent('type', () => 'EcdsaSecp256k1RecoverySignature2020');
  jsonObject.putIfAbsent('proofPurpose', () => 'assertionMethod');
  jsonObject.putIfAbsent('verificationMethod', () => verificationMethod);
  jsonObject.putIfAbsent(
      'created', () => DateTime.now().toUtc().toIso8601String());

  if (domain != null) {
    jsonObject.putIfAbsent('domain', () => domain);
  }

  if (challenge != null) {
    jsonObject.putIfAbsent('challenge', () => challenge);
  }

  return json.encode(jsonObject);
}

util.ECDSASignature _getSignatureFromJws(String jws) {
  var splitJws = jws.split('.');
  var sigArray = base64Decode(splitJws[2]);
  if (sigArray.length != 65) throw Exception('wrong signature');
  return new util.ECDSASignature(bytesToInt(sigArray.sublist(0, 32)),
      bytesToInt(sigArray.sublist(32, 64)), sigArray[64] + 27);
}
