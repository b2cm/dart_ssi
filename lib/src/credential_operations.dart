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
/// "id": "did:ethr:0x82734",
/// "hashAlg" : "keccak-256",
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
String buildPlaintextCredential(dynamic credential, String holderDid,
    {bool addHashAlg = true}) {
  Map<String, dynamic> credMap = credentialToMap(credential);
  Map<String, dynamic> finalCred = new Map();

  if (credMap.containsKey('credentialSubject')) {
    credMap = credMap['credentialSubject'];
  }
  if (credMap.containsKey('@context')) {
    finalCred['@context'] = credMap['@context'];
    credMap.remove('@context');
  }

  if (holderDid != '') {
    finalCred['id'] = holderDid;
  }
  if (addHashAlg) finalCred['hashAlg'] = 'keccak-256';

  credMap.forEach((key, value) {
    if (key == 'type' || key == '@type') {
      finalCred[key] = value;
    } else if (value is String || value is num || value is bool) {
      finalCred[key] = _hashStringOrNum(value);
    } else if (value is List) {
      List<Map<String, dynamic>> newValue = [];
      value.forEach((element) {
        if (element is String || element is num || element is bool)
          newValue.add(_hashStringOrNum(element));
        else if (element is Map<String, dynamic>) {
          newValue.add(jsonDecode(
              buildPlaintextCredential(element, '', addHashAlg: false)));
        } else
          throw Exception('unknown type with key $key');
      });
      finalCred[key] = newValue;
    } else if (value is Map<String, dynamic>) {
      finalCred[key] =
          jsonDecode(buildPlaintextCredential(value, '', addHashAlg: false));
    } else {
      throw Exception('unknown datatype  with key $key');
    }
  });

  return jsonEncode(finalCred);
}

/// Builds a credential conform to W3C-Standard, which includes all hashes a
/// plaintext-credential [credential] contains.
String buildW3cCredentialwithHashes(dynamic credential, String issuerDid,
    {dynamic type, dynamic context, String revocationRegistryAddress}) {
  var plaintectMap = credentialToMap(credential);
  var hashCred = _collectHashes(credential, id: plaintectMap['id']);

  List<String> credTypes = [];
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

  List<String> credContext = [];
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
  var plaintextCredMap = credentialToMap(credential);
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
  var w3cMap = credentialToMap(w3cCred);
  var plainMap = credentialToMap(plaintext);
  if (w3cMap.containsKey('credentialSubject'))
    w3cMap = w3cMap['credentialSubject'];
  if (plainMap['id'] != w3cMap['id'])
    throw Exception('Ids of given credentials do not match');
  if (plainMap['hashAlg'] != 'keccak-256')
    throw Exception(
        'Hashing Algorithm ${plainMap['hashAlg']} is not supported');
  return _checkHashes(w3cMap, plainMap);
}

/// Signs a W3C-Standard conform [credential] with the private key for issuer-did in the credential.
String signCredential(WalletStore wallet, dynamic credential) {
  credential = credentialToMap(credential);
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
Future<bool> verifyCredential(dynamic credential,
    {Erc1056 erc1056, String rpcUrl}) async {
  Map<String, dynamic> credMap = credentialToMap(credential);
  if (!credMap.containsKey('proof')) {
    throw Exception('no proof section found');
  }
  if (rpcUrl != null) {
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
  }

  Map<String, dynamic> proof = credMap['proof'];
  credMap.remove('proof');
  var credHash = util.sha256(jsonEncode(credMap));
  var issuerDid = getIssuerDidFromCredential(credential);
  if (erc1056 != null) issuerDid = await erc1056.identityOwner(issuerDid);
  return _verifyProof(proof, credHash, issuerDid);
}

/// Builds a presentation for [credentials].
///
/// If not only the ownership od the dids in the credentials should be proofed a List of [additionalDids]
/// could be given and a proof section for each did is added.
String buildPresentation(
    List<dynamic> credentials, WalletStore wallet, String challenge,
    {List<String> additionalDids, List<dynamic> disclosedCredentials}) {
  List<Map<String, dynamic>> credMapList = [];
  List<String> holderDids = [];
  credentials.forEach((element) {
    var credMap = credentialToMap(element);
    credMapList.add(credMap);
    holderDids.add(getHolderDidFromCredential(credMap));
  });
  var presentation = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
    ],
    'type': ['VerifiablePresentation'],
    'verifiableCredential': credMapList
  };

  if (disclosedCredentials != null) {
    List<Map<String, dynamic>> disclosedCreds = [];
    disclosedCredentials.forEach((element) {
      var credMap = credentialToMap(element);
      disclosedCreds.add(credMap);
    });
    presentation['disclosedCredentials'] = disclosedCreds;
    var type = presentation['type'] as List<String>;
    type.add('DisclosedCredentialPresentation');
    presentation['type'] = type;
  }

  var presentationHash = util.sha256(jsonEncode(presentation));
  List<Map<String, dynamic>> proofList = [];
  holderDids.forEach((element) {
    var proof = _buildProof(presentationHash, element, wallet,
        proofOptions: _buildProofOptions(
            verificationMethod: element, challenge: challenge));
    proofList.add(proof);
  });
  if (additionalDids != null) {
    additionalDids.forEach((element) {
      var proof = _buildProof(presentationHash, element, wallet,
          proofOptions: _buildProofOptions(
              verificationMethod: element, challenge: challenge));
      proofList.add(proof);
    });
  }
  presentation['proof'] = proofList;
  return jsonEncode(presentation);
}

/// Verifies the [presentation].
///
/// It uses erc1056 to look up the current owner of the dids a proof is given in [presentation].
Future<bool> verifyPresentation(dynamic presentation, String challenge,
    {Erc1056 erc1056, String rpcUrl}) async {
  var presentationMap = credentialToMap(presentation);
  var proofs = presentationMap['proof'] as List;
  presentationMap.remove('proof');
  var presentationHash = util.sha256(jsonEncode(presentationMap));

  var credentials = presentationMap['verifiableCredential'] as List;
  List<String> holderDids = [];
  await Future.forEach(credentials, (element) async {
    if (!(await verifyCredential(element, erc1056: erc1056, rpcUrl: rpcUrl)))
      throw Exception('A credential could not been verified');
    else {
      var did = getHolderDidFromCredential(element);
      if (erc1056 != null) did = await erc1056.identityOwner(did);
      holderDids.add(did);
    }
  });

  await Future.forEach(proofs, (element) async {
    var verifMeth = element['verificationMethod'];
    var includedNonce = element['challenge'];
    if (includedNonce != challenge) throw Exception('Challenge does not match');
    if (erc1056 != null) verifMeth = await erc1056.identityOwner(verifMeth);
    if (holderDids.contains(verifMeth)) holderDids.remove(verifMeth);
    if (!_verifyProof(element, presentationHash, verifMeth))
      throw Exception('Proof for $verifMeth could not been verified');
  });
  if (holderDids.isNotEmpty) throw Exception('There are dids without a proof');

  if (presentationMap.containsKey('disclosedCredentials')) {
    var disclosedCredentials = presentationMap['disclosedCredentials'] as List;
    Map<String, Map<String, dynamic>> credsToId = {};
    credentials.forEach((element) {
      var did = getHolderDidFromCredential(element);
      credsToId[did] = element;
    });

    disclosedCredentials.forEach((element) =>
        compareW3cCredentialAndPlaintext(credsToId[element['id']], element));
  }
  return true;
}

///Discloses all values in [valuesToDisclose] of [plaintextCredential].
///
/// [valuesToDisclose] contains the keys of the attributes, that should be disclosed.
/// Keys in nested object should be separeted with . (point) from the parent-key, like here:
/// Imagine your plaintext Credential look like this:
/// ```
/// {
///   "@context": [
///     "https://bccm-ssi.hs-mittweida.de/credentials"
///   ],
///   "type": "ImmatrikulationCredential",
///   "issuanceDate": {
///     "value": "2021-03-09",
///     "salt": "0830fac0-ae9e-4097-85b0-03ddb3557eb6",
///     "hash": "0x9e51f7c66036d0eb2fcc3c1c5d9da18f96ae880681a676dcc92a3be22e4d7523"
///   },
///   "student": {
///     "type": "Student",
///     "givenName": {
///       "value": "Max",
///       "salt": "b36a876c-2029-417a-93fb-b4daf75ed959",
///       "hash": "0x30aa2b081c358aafdbbeb9436a167ee9e5bb003a8bd892ef33d50ba78ce1834e"
///     },
///     "familyName": {
///       "value": "Mustermann",
///       "salt": "2f55f35d-72a9-4986-8986-93d4e4d6f3bf",
///       "hash": "0x6be6118a83dd2b1c5a050da46ea301fe5512245d9cfb9966b88219b1ee54e8ba"
///     },
///     "address": {
///       "type": "PostalAddress",
///       "addressLocality": {
///         "value": "Mittweida",
///         "salt": "40f1403a-984f-41ed-8821-b987fe556a36",
///         "hash": "0x97144b9ff02df331935d394cd790a1ab76bf9c6a5b0747c3f03db931103cdf56"
///       },
///       "postalCode": {
///         "value": "09648",
///         "salt": "83cd01c2-0a30-4907-b8cd-0bd5808a217e",
///         "hash": "0x254cfac1490b2f8330925374de8a40b8c6d5efe41b3f80e0fe67c3c8cf783b8f"
///       },
///       "streetAddress": {
///         "value": "Am Schwanenteich 8",
///         "salt": "6fd7baf8-f798-4fde-86e2-d19203d9caf6",
///         "hash": "0x4b2e396e631e5a391cf6415bd3110fa420fc7167509ef15407ee48b6f827be9c"
///       }
///     }
///   }
///}
///```
///and you only want to show your familyName and the postalCode of your living place,
/// a working call of this function would be :
/// ```discloseValues(plaintextCredential, [issuanceDate, student.givenName, student.address.addressLocality, student.address.streetAddress])
/// ```
/// If there is an array in the plaintext-Credential the array elements that should be disclosed,
/// could be given as follows: arrayKey.arrayIndex e.g. friends.1. ArrayIndex starts with 0.
String discloseValues(
    dynamic plaintextCredential, List<String> valuesToDisclose) {
  Map<String, dynamic> plaintextMap = credentialToMap(plaintextCredential);
  Map<String, dynamic> result = {};
  plaintextMap.forEach((key, value) {
    result[key] = value;
    if (!(key == '@context' ||
        key == 'type' ||
        key == '@type' ||
        key == 'id' ||
        key == 'hashAlg')) {
      // if key is in map it should be a single string
      if (_hashedAttributeSchemaStrict.validate(value)) {
        // check if key should be disclosed
        if (valuesToDisclose.contains(key)) {
          result[key] = {'hash': value['hash']};
        }
      }
      // new Object found
      else if (_mapOfHashedAttributesSchema.validate(value)) {
        List<String> valuesSeen = [];
        List<String> valuesToDiscloseNew = [];
        //search in valuesToDisclose if sth. starts with key
        valuesToDisclose.forEach((element) {
          if (valuesSeen.contains(element)) {
          }
          //key of Object is in List
          else if (element == key) {
            Map<String, dynamic> valueMap = value as Map<String, dynamic>;
            valuesToDiscloseNew = valueMap.keys.toList();
          }
          // subkeys of Object are in List
          else if (element.split('.').first == key) {
            valuesToDiscloseNew.add(element.substring(key.length + 1));
            valuesSeen.add(element);
          }
        });
        var newValue = jsonDecode(discloseValues(value, valuesToDiscloseNew));
        result[key] = newValue;
      }
      // array found
      else if (value is List) {
        result[key] = value;
        List<String> valuesSeen = [];
        valuesToDisclose.forEach((element) {
          if (valuesSeen.contains(element)) {
          }
          //whole Array should be disclosed
          else if (element == key) {
            List<String> valuesToDiscloseNew = [];
            for (var i = 0; i < value.length; i++) {
              valuesToDiscloseNew.add('$key.$i');
            }
            result[key] = jsonDecode(
                discloseValues({key: value}, valuesToDiscloseNew))[key];
          }
          //elementwise disclosing
          else if (element.split('.').first == key) {
            int arrayIndex = int.parse(element.split('.')[1]);
            if (_hashedAttributeSchemaStrict.validate(value[arrayIndex])) {
              result[key]
                  [arrayIndex] = result[key][arrayIndex] as Map<String, dynamic>
                ..remove('value')
                ..remove('salt');
            }
            //Object in Array
            else if (_mapOfHashedAttributesSchema.validate(value[arrayIndex])) {
              //search in given keys, if sth. else should be disclosed
              List<String> valuesToDiscloseNew = [];
              valuesToDisclose.forEach((element) {
                if (element.split('.')[0] == key &&
                    int.parse(element.split('.')[1]) == arrayIndex) {
                  if (element.split('.').length > 2) {
                    valuesSeen.add(element);
                    valuesToDiscloseNew.add(element.substring(
                        key.length + 1 + arrayIndex.toString().length + 1));
                  } else {
                    valuesToDiscloseNew =
                        (value[arrayIndex] as Map<String, dynamic>)
                            .keys
                            .toList();
                  }
                }
              });
              result[key][arrayIndex] = jsonDecode(
                  discloseValues(value[arrayIndex], valuesToDiscloseNew));
            } else {
              throw Exception(
                  'Malformed array element in array with key $key at index $arrayIndex');
            }
          }
        });
      } else {
        throw Exception('Unknown data type at key $key');
      }
    }
  });
  return jsonEncode(result);
}

/// Returns all json-paths of the relevant keys used in the credentialSubject-part of a [w3cCredential].
List<String> getAllJsonPathsOfCredential(dynamic w3cCredential) {
  var cred = credentialToMap(w3cCredential);
  if (cred.containsKey('credentialSubject')) cred = cred['credentialSubject'];
  List<String> paths = [];
  cred.forEach((key, value) {
    if (!(key == 'type' ||
        key == '@type' ||
        key == '@context' ||
        key == 'id')) {
      if (value is String || value is num || value is bool)
        paths.add(key);
      else if (value is Map) {
        var objectPaths = getAllJsonPathsOfCredential(value);
        objectPaths.forEach((element) {
          paths.add('$key.$element');
        });
      } else if (value is List) {
        for (int i = 0; i < value.length; i++) {
          if (value[i] is String || value[i] is num || value[i] is bool)
            paths.add('$key.$i');
          else if (value[i] is Map) {
            var objectPaths = getAllJsonPathsOfCredential(value[i]);
            objectPaths.forEach((element) {
              paths.add('$key.$i.$element');
            });
          } else
            throw Exception(
                'Malformed array element in array with key $key at index $i');
        }
      } else
        throw Exception('Unknown data type at key $key');
    }
  });

  return paths;
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
  return base64UrlEncode(utf8.encode(jsonString));
}

/// Collects the did of the issuer of a [credential].
String getIssuerDidFromCredential(dynamic credential) {
  var credentialMap = credentialToMap(credential);

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
  var credMap = credentialToMap(credential);
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

/// Signs the given String [toSign] with key-pair of [didToSignWith].
///
/// Returned signature is formatted as jws. If a detached jws (header..signature) should be returned [detached] must be set to true.
/// If no custom [jwsHeader] is given, the default one is
/// ```
/// {
///   "alg" : "ES256K-R",
///   "b64" : false,
///   "crit" : ["b64"]
/// }
/// ```
/// If a custom one should be used, it has to be given in ist json representation (dart String or Map) and the value of alg has to be ES256K-R,
/// because for now this is the only supported signature algorithm.
String signString(WalletStore wallet, String didToSignWith, String toSign,
    {bool detached = false, dynamic jwsHeader}) {
  String header;
  if (jwsHeader != null) {
    Map<String, dynamic> headerMap;
    if (jwsHeader is String)
      headerMap = jsonDecode(jwsHeader);
    else
      headerMap = jwsHeader;
    if (headerMap['alg'] != 'ES256K-R')
      throw Exception('Unsupported signature algorithm ${headerMap['alg']}');
    header = _removePaddingFromBase64(
        base64UrlEncode(utf8.encode(jsonEncode(headerMap))));
  } else {
    var critical = new Map<String, dynamic>();
    critical['b64'] = false;
    header = _removePaddingFromBase64(
        buildJwsHeader(alg: 'ES256K-R', extra: critical));
  }
  var payload = _removePaddingFromBase64(base64UrlEncode(utf8.encode(toSign)));
  var signingInput = '$header.$payload';
  var hash = util.sha256(ascii.encode(signingInput));
  String privKeyHex;

  privKeyHex = wallet.getPrivateKeyToCredentialDid(didToSignWith);
  if (privKeyHex == null)
    privKeyHex = wallet.getPrivateKeyToConnectionDid(didToSignWith);
  if (privKeyHex == null) throw Exception('Could not find private key');
  var key = EthPrivateKey.fromHex(privKeyHex);
  MsgSignature signature = sign(hash, key.privateKey);
  var sigArray = intToBytes(signature.r) +
      intToBytes(signature.s) +
      util.intToBuffer(signature.v - 27);

  if (detached)
    return '$header.'
        '.${_removePaddingFromBase64(base64UrlEncode(sigArray))}';
  else
    return '$header.$payload'
        '.${_removePaddingFromBase64(base64UrlEncode(sigArray))}';
}

/// Verifies the signature in [jws]. If a detached jws is given the signed string must be given separately as [toSign].
Future<bool> verifyStringSignature(String jws, String expectedDid,
    {String toSign, Erc1056 erc1056}) async {
  var splitted = jws.split('.');
  if (splitted.length != 3) throw Exception('Malformed JWS');
  var signature = _getSignatureFromJws(jws);
  String payload;
  if (splitted[1] != '')
    payload = splitted[1];
  else if (toSign != null)
    payload = _removePaddingFromBase64(base64UrlEncode(utf8.encode(toSign)));
  else
    throw Exception('No payload given');
  var signingInput = '${splitted[0]}.$payload';
  var hashToSign = util.sha256(ascii.encode(signingInput));
  var pubKey = util.recoverPublicKeyFromSignature(signature, hashToSign);
  var recoveredDid =
      'did:ethr:${EthereumAddress.fromPublicKey(pubKey).hexEip55}';
  if (erc1056 != null) expectedDid = await erc1056.identityOwner(expectedDid);

  return recoveredDid == expectedDid;
}

/// Converts json-String [credential] to dart Map.
Map<String, dynamic> credentialToMap(dynamic credential) {
  if (credential is String)
    return jsonDecode(credential);
  else if (credential is Map<String, dynamic>)
    return credential;
  else
    throw Exception('unknown type for $credential');
}

//***********************Private Methods***************************************

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
  var credMap = credentialToMap(credential);
  Map<String, dynamic> hashCred = new Map();
  if (id != null) hashCred['id'] = id;
  credMap.forEach((key, value) {
    if (key != '@context') {
      if (key == 'type' || key == '@type' || key == 'id')
        hashCred[key] = value;
      else if (key == 'hashAlg') {
      } else if (value is List) {
        List<dynamic> hashList = [];
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
    if (!(key == '@context' ||
        key == 'type' ||
        key == '@type' ||
        key == 'id' ||
        key == 'hashAlg')) {
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
    if (proofOptions is String)
      pOptions = proofOptions;
    else
      pOptions = jsonEncode(proofOptions);
  }

  var pOptionsHash = util.sha256(pOptions);
  var hash = util.sha256(pOptionsHash + hashToSign);
  var privKeyHex = wallet.getPrivateKeyToCredentialDid(didToSignWith);
  if (privKeyHex == null)
    privKeyHex = wallet.getPrivateKeyToConnectionDid(didToSignWith);
  if (privKeyHex == null) throw Exception('Could not find a private key');
  var key = EthPrivateKey.fromHex(privKeyHex);
  MsgSignature signature = sign(hash, key.privateKey);
  var sigArray = intToBytes(signature.r) +
      intToBytes(signature.s) +
      util.intToBuffer(signature.v - 27);

  Map<String, dynamic> optionsMap = jsonDecode(pOptions);

  var critical = new Map<String, dynamic>();
  critical['b64'] = false;
  optionsMap['jws'] = '${buildJwsHeader(alg: 'ES256K-R', extra: critical)}.'
      '.${base64UrlEncode(sigArray)}';

  return optionsMap;
}

bool _verifyProof(Map<String, dynamic> proof, Uint8List hash, String did) {
  var signature = _getSignatureFromJws(proof['jws']);

  proof.remove('jws');
  if (proof['type'] != 'EcdsaSecp256k1RecoverySignature2020')
    throw Exception('Proof type ${proof['type']} is not supported');
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
  Map<String, dynamic> header =
      jsonDecode(utf8.decode(base64Decode(_addPaddingToBase64(splitJws[0]))));
  if (header['alg'] != 'ES256K-R')
    throw Exception('Unsupported signature Algorithm ${header['alg']}');
  var sigArray = base64Decode(_addPaddingToBase64(splitJws[2]));
  if (sigArray.length != 65) throw Exception('wrong signature-length');
  return new util.ECDSASignature(bytesToInt(sigArray.sublist(0, 32)),
      bytesToInt(sigArray.sublist(32, 64)), sigArray[64] + 27);
}

String _addPaddingToBase64(String base64Input) {
  while (base64Input.length % 4 != 0) base64Input += '=';
  return base64Input;
}

String _removePaddingFromBase64(String base64Input) {
  while (base64Input.endsWith('='))
    base64Input = base64Input.substring(0, base64Input.length - 1);
  return base64Input;
}
