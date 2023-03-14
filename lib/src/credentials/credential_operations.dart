import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/src/credentials/revocation_list_2020.dart';
import 'package:http/http.dart';
import 'package:json_ld_processor/json_ld_processor.dart';
import 'package:json_path/json_path.dart';
import 'package:json_schema2/json_schema2.dart';
import 'package:uuid/uuid.dart';
import 'package:web3dart/credentials.dart';
import 'package:web3dart/crypto.dart';

import '../dids/did_ethr.dart';
import '../util/utils.dart';
import '../wallet/wallet_store.dart';

final _hashedAttributeSchemaMap = {
  "type": "object",
  "properties": {
    "value": {
      "type": ["number", "string", "boolean"]
    },
    "salt": {"type": "string"}
  },
  "additionalProperties": false
};
final _hashedAttributeSchema =
    JsonSchema.createSchema(_hashedAttributeSchemaMap);

final _hashedAttributeSchemaStrict = JsonSchema.createSchema({
  "type": "object",
  "required": ["salt", "value"],
  "properties": {
    "value": {
      "type": ["number", "string", "boolean"]
    },
    "salt": {"type": "string"}
  },
  "additionalProperties": false
});

final _mapOfHashedAttributesSchema = JsonSchema.createSchema({
  'type': 'object',
  'properties': {r'^.*$': _hashedAttributeSchemaMap}
});

/// Builds a json-Object where every Attribute gets a value and salt from json-Object [credential].
///
/// E.g.
/// ```
/// {
///   "type" : "NameAgeCredential",
///   "name" : "Max",
///   "age" : 20
/// }
/// ```
/// becomes to
///```
///{
/// "id": "did:ethr:0x82734",
/// "type": ["HashedPlaintextCredential2021","NameAgeCredential"],
/// "hashAlg" : "keccak-256",
/// "name":
/// {
///   "value":"Max",
///   "salt":"dc0931a0-60c6-4bc8-a27d-b3fd13e62c63"
///  },
///  "age":
///   {
///   "value":20,
///   "salt":"3e9bacd3-aa74-42c1-9895-e490e3931a73"
///  }
/// }
/// ```
/// where salt is a Version 4 UUID.
/// [credential] could be a string or Map<String, dynamic> representing a valid json-Object.
String buildPlaintextCredential(dynamic credential, String? holderDid,
    {bool addHashAlg = true}) {
  Map<String, dynamic> credMap = credentialToMap(credential);
  Map<String, dynamic> finalCred = {};

  if (credMap.containsKey('credentialSubject')) {
    credMap = credMap['credentialSubject'];
  }
  if (credMap.containsKey('@context')) {
    finalCred['@context'] = credMap['@context'];
    credMap.remove('@context');
  }

  if (addHashAlg) {
    List<String> types = [];
    types.add('HashedPlaintextCredential2021');
    if (credMap.containsKey('type') || credMap.containsKey('@type')) {
      var value = credMap['type'];
      credMap.remove('type');
      if (value == null) {
        value = credMap['@type'];
        credMap.remove('@type');
      }
      if (value is String) {
        if (!types.contains(value)) types.add(value);
      } else if (value is List) {
        for (var element in value) {
          if (!types.contains(element)) types.add(element);
        }
      } else {
        throw Exception('Unsupported datatype for type key');
      }
      finalCred['type'] = types;
    }
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
      List<Map<String, dynamic>?> newValue = [];
      for (var element in value) {
        if (element is String || element is num || element is bool) {
          newValue.add(_hashStringOrNum(element));
        } else if (element is Map<String, dynamic>) {
          newValue.add(jsonDecode(
              buildPlaintextCredential(element, '', addHashAlg: false)));
        } else {
          throw Exception('unknown type with key $key');
        }
      }
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
///
/// [issuerInformation] is a valid json Object (dart string or map) containing additional Information about the issuer, e.g its homepage or name.
///
/// [revocationRegistryAddress] is a valid Ethereum-Address of a SmartContract capable of showing the revocation Status of the credential.
String buildW3cCredentialwithHashes(dynamic credential, String? issuerDid,
    {dynamic type,
    dynamic context,
    dynamic issuerInformation,
    DateTime? validUntil,
    String? revocationRegistryAddress}) {
  var plaintextMap = credentialToMap(credential);
  var hashCred =
      _collectHashes(credential, id: plaintextMap['id'], firstLevel: true);

  List<String> credTypes = [];
  credTypes.add('VerifiableCredential');
  if (type != null) {
    if (type is String) {
      if (type != 'VerifiableCredential') credTypes.add(type);
    } else if (type is List<String>) {
      type.remove('VerifiableCredential');
      credTypes.addAll(type);
    } else {
      throw Exception('type has unknown datatype');
    }
  }

  List<dynamic> credContext = [];
  credContext.add('https://www.w3.org/2018/credentials/v1');
  if (context != null) {
    if (context is String) {
      if (context != 'https://www.w3.org/2018/credentials/v1') {
        credContext.add(context);
      }
    } else if (context is List<String>) {
      if (context.contains('https://www.w3.org/2018/credentials/v1')) {
        context.remove('https://www.w3.org/2018/credentials/v1');
      }
      credContext += context;
    } else if (context is Map) {
      credContext.add(context);
    } else if (context is List) {
      credContext += context;
    } else {
      throw Exception('context has unknown datatype');
    }
  }
  // adding context of Plaintext-credential
  var plaintextCredMap = credentialToMap(credential);
  if (plaintextCredMap.containsKey('@context')) {
    var context = plaintextCredMap['@context'];
    if (context is List) {
      for (var element in context) {
        if (!credContext.contains(element)) {
          credContext.add(element);
        }
      }
    } else if (context is String) {
      if (!credContext.contains(context)) credContext.add(context);
    } else {
      throw Exception('@context has unsupported type');
    }
  }

  var issuerInfo = {};
  if (issuerInformation != null) {
    issuerInfo = credentialToMap(issuerInformation);
    issuerInfo['id'] = issuerDid;
  }

  var w3cCred = {
    '@context': credContext,
    'type': credTypes,
    'credentialSubject': jsonDecode(hashCred),
    'issuer': issuerInfo.isEmpty ? issuerDid : issuerInfo,
    'issuanceDate': DateTime.now().toUtc().toIso8601String()
  };

  if (validUntil != null) {
    w3cCred['expirationDate'] = validUntil.toIso8601String();
  }

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
  if (w3cMap.containsKey('credentialSubject')) {
    w3cMap = w3cMap['credentialSubject'];
  }
  if (plainMap['id'] != w3cMap['id']) {
    throw Exception('Ids of given credentials do not match');
  }
  if (plainMap['hashAlg'] != 'keccak-256') {
    throw Exception(
        'Hashing Algorithm ${plainMap['hashAlg']} is not supported');
  }
  return _checkHashes(w3cMap, plainMap);
}

/// Signs a W3C-Standard conform [credentialToSign] with the private key for issuer-did in the credential.
Future<String> signCredential(WalletStore wallet, dynamic credentialToSign,
    {String? challenge,
    Signer? signer,
    Function(Uri url, LoadDocumentOptions? options) loadDocumentFunction =
        loadDocumentStrict}) async {
  Map<String, dynamic> credential;
  if (credentialToSign is VerifiableCredential) {
    credential = credentialToSign.toJson();
  } else {
    credential = credentialToMap(credentialToSign);
  }

  String issuerDid = getIssuerDidFromCredential(credential);
  if (issuerDid == '') {
    throw Exception('Could not examine IssuerDID');
  }
  signer ??= _determineSignerForDid(issuerDid, loadDocumentFunction);
  credential['proof'] = await signer.buildProof(credential, wallet, issuerDid,
      challenge: challenge);
  return jsonEncode(credential);
}

Signer _determineSignerForDid(String did,
    Function(Uri url, LoadDocumentOptions? options)? loadDocumentFunction) {
  if (did.startsWith('did:key:z6Mk')) {
    return EdDsaSigner(loadDocumentFunction);
  } else if (did.startsWith('did:ethr')) {
    return EcdsaRecoverySignature(loadDocumentFunction);
  } else {
    throw Exception('could not examine signature type');
  }
}

Signer _determineSignerForType(String type,
    Function(Uri url, LoadDocumentOptions? options) loadDocumentFunction) {
  if (type == 'Ed25519Signature2020') {
    return EdDsaSigner(loadDocumentFunction);
  } else if (type == 'EcdsaSecp256k1RecoverySignature2020') {
    return EcdsaRecoverySignature(loadDocumentFunction);
  } else {
    throw Exception('could not examine signature type');
  }
}

/// Verifies the signature for the given [credential].
///
/// [credential] may be of datatype Map<String, dynamic>, (jsonEncoded) String or [VerifiableCredential].
///
/// If an [erc1056] instance is given it is used to determine the current ethereum-Address behind a did.
///
/// If the credential contains a `credentialStatus` property, the revocation status is checked.
/// In case of credentialStatus type `EthereumRevocationList` [revocationRegistry] is needed.
///
/// Only in case the credential Signature is valid and the credential is not revoked or suspended true is returned,
/// otherwise an Exception is thrown. There are two different types of Exceptions in use: [RevokedException] and [SignatureException].
/// Both use codes to indicate why the credential is invalid. If a SignatureException has the code `sig` the signature itself is invalid,
/// if it has the code `sigErr` something went wrong during signature check.
/// If a RevokedException has code `rev` or `sus` the credential was revoked or suspended, if it has code `revErr` something went wrong during revocation check.
Future<bool> verifyCredential(dynamic credential,
    {Erc1056? erc1056,
    RevocationRegistry? revocationRegistry,
    String? expectedChallenge,
    Signer Function(
            String typeMatch,
            Function(Uri url, LoadDocumentOptions? options)
                loadDocumentFunction)
        signerSelector = _determineSignerForType,
    Function(Uri url, LoadDocumentOptions? options) loadDocumentFunction =
        loadDocumentStrict}) async {
  Map<String, dynamic> credMap;
  if (credential is VerifiableCredential) {
    credMap = credential.toJson();
  } else {
    credMap = credentialToMap(credential);
  }
  if (!credMap.containsKey('proof')) {
    throw Exception('no proof section found');
  }

  // determine issuer
  var issuerDid = getIssuerDidFromCredential(credential);
  if (erc1056 != null) issuerDid = await erc1056.identityOwner(issuerDid);

  // verify proof
  Map<String, dynamic> proof = credMap['proof'];
  var signer = signerSelector.call(proof['type'], loadDocumentFunction);
  credMap.remove('proof');
  var verified = true;
  try {
    verified = await signer.verifyProof(proof, credMap, issuerDid,
        challenge: expectedChallenge);
  } catch (_) {
    credMap['proof'] = proof;
    throw SignatureException('Unable to verify credential Signature', 'sigErr');
  }
  credMap['proof'] = proof;
  if (!verified) {
    throw SignatureException('Credentials Signature incorrect', 'sig');
  }

  // check for Revocation
  if (credMap.containsKey('credentialStatus')) {
    var credStatus = credMap['credentialStatus'];

    if (credStatus['type'] == 'EthereumRevocationList') {
      if (revocationRegistry != null) {
        revocationRegistry.setContract(credStatus['id']);
        var revoked = await revocationRegistry
            .isRevoked(getHolderDidFromCredential(credMap));
        if (revoked) throw RevokedException('Credential was revoked', 'rev');
      } else {
        throw RevokedException('Revocation contract needed', 'revErr');
      }
    } else if (credStatus['type'] == 'RevocationList2020Status') {
      var status = RevocationList2020Status.fromJson(credStatus);
      var res = await get(Uri.parse(status.revocationListCredential),
              headers: {'Accept': 'application/json'})
          .timeout(Duration(seconds: 30), onTimeout: () {
        return Response('Timeout', 408);
      });

      if (res.statusCode == 200) {
        var revCred = RevocationList2020Credential.fromJson(res.body);
        try {
          await verifyCredential(revCred);
        } on SignatureException catch (_) {
          throw RevokedException(
              'could not verify RevocationListCredential', 'revErr');
        }

        var revoked = revCred.isRevoked(int.parse(status.revocationListIndex));
        if (revoked) {
          throw RevokedException('Credential is revoked', 'rev');
        }
      } else {
        throw RevokedException(
            'Error loading status list from ${status.revocationListCredential}',
            'revErr');
      }
    } else if (credStatus['type'] == 'StatusList2021Entry') {
      var status = StatusList2021Entry.fromJson(credStatus);
      var res = await get(Uri.parse(status.statusListCredential),
              headers: {'Accept': 'application/json'})
          .timeout(Duration(seconds: 30), onTimeout: () {
        return Response('Timeout', 408);
      });

      if (res.statusCode == 200) {
        var revCred = StatusList2021Credential.fromJson(res.body);

        if (revCred.statusPurpose != status.statusPurpose) {
          throw RevokedException(
              'StatusPurpose of StatusListEntry and StatusListCredential do not match',
              'revErr');
        }
        try {
          await verifyCredential(revCred);
        } on SignatureException catch (_) {
          throw RevokedException(
              'could not verify RevocationListCredential', 'revErr');
        }

        var revoked = revCred.isRevoked(int.parse(status.statusListIndex));
        if (revoked) {
          throw RevokedException(
              'Credential is ${status.statusPurpose == CredentialStatus2021Purpose.revocation ? 'revoked' : 'suspended'}',
              status.statusPurpose == CredentialStatus2021Purpose.revocation
                  ? 'rev'
                  : 'sus');
        }
      } else {
        throw RevokedException(
            'Error loading status list from ${status.statusListCredential}',
            'revErr');
      }
    } else {
      throw RevokedException(
          'Unknown Status-method : ${credStatus['type']}', 'revErr');
    }
  }

  return verified;
}

class RevokedException implements Exception {
  String message;
  String code;

  RevokedException(this.message, this.code);
}

class SignatureException implements Exception {
  String message;
  String code;

  SignatureException(this.message, this.code);
}

/// Builds a presentation for [credentials].
///
/// If not only the ownership of the dids in the credentials should be proofed a List of [additionalDids]
/// could be given and a proof section for each did is added.
Future<String> buildPresentation(
    List<dynamic>? credentials, WalletStore wallet, String challenge,
    {String? holder,
    List<String>? additionalDids,
    List<dynamic>? disclosedCredentials,
    Function(Uri url, LoadDocumentOptions? options) loadDocumentFunction =
        loadDocumentStrict}) async {
  List<Map<String, dynamic>?> credMapList = [];
  List<String?> holderDids = [];

  PresentationSubmission? submission;
  if (credentials != null) {
    for (var element in credentials) {
      if (element is FilterResult) {
        List<InputDescriptorMappingObject> mapping = [];
        if (submission != null) {
          mapping = submission.descriptorMap;
        }
        for (var cred in element.credentials) {
          var credEntry = cred.toJson();
          credMapList.add(credEntry);
          holderDids.add(getHolderDidFromCredential(credEntry));
          for (var descriptor in element.matchingDescriptorIds) {
            var map = InputDescriptorMappingObject(
                id: descriptor,
                format: 'ldp_vc',
                path: JsonPath(
                    '\$.verifiableCredential[${credMapList.length - 1}]'));
            mapping.add(map);
          }
        }
        submission = PresentationSubmission(
            presentationDefinitionId: element.presentationDefinitionId,
            descriptorMap: mapping);
      } else {
        Map<String, dynamic> credMap;
        if (element is VerifiableCredential) {
          credMap = element.toJson();
        } else {
          credMap = credentialToMap(element);
        }
        credMapList.add(credMap);
        holderDids.add(getHolderDidFromCredential(credMap));
      }
    }
  }

  if (holder != null) {
    holderDids.add(holder);
  }

  if (holderDids.isEmpty) {
    throw Exception('No holder did given. Can\'t generate Presentation');
  }

  //TODO dynamically build context based on proof methods
  List<String> context = [
    'https://www.w3.org/2018/credentials/v1',
    ed25519ContextIri
  ];
  List<String> type = ['VerifiablePresentation'];
  if (submission != null) {
    context.add(
        'https://identity.foundation/presentation-exchange/submission/v1/');
    type.add('PresentationSubmission');
  }

  Map<String, dynamic> presentation = {'@context': context, 'type': type};

  if (credMapList.isNotEmpty) {
    presentation['verifiableCredential'] = credMapList;
  }

  if (holder != null) {
    presentation['holder'] = holder;
  }

  if (submission != null) {
    presentation['presentation_submission'] = submission.toJson();
  }

  if (disclosedCredentials != null) {
    List<Map<String, dynamic>?> disclosedCreds = [];
    for (var element in disclosedCredentials) {
      var credMap = credentialToMap(element);
      disclosedCreds.add(credMap);
    }
    presentation['disclosedCredentials'] = disclosedCreds;
    var type = presentation['type'] as List<String?>;
    type.add('DisclosedCredentialPresentation');
    presentation['type'] = type;
  }

  // build signatures
  List<Map<String, dynamic>> proofList = [];
  Set<Type> signerTypes = {};
  for (var element in holderDids) {
    var signer = _determineSignerForDid(element!, loadDocumentFunction);
    signerTypes.add(signer.runtimeType);
    proofList.add(await signer.buildProof(presentation, wallet, element,
        challenge: challenge, proofPurpose: 'authentication'));
  }

  if (additionalDids != null) {
    for (var element in additionalDids) {
      var signer = _determineSignerForDid(element, loadDocumentFunction);
      var t = signer.runtimeType;
      if (t == EcdsaRecoverySignature &&
          !context.contains(ecdsaRecoveryContextIri)) {
        context.add(ecdsaRecoveryContextIri);
      } else if (t == EdDsaSigner && !context.contains(ed25519ContextIri)) {
        context.add(ed25519ContextIri);
      }
      proofList.add(await signer.buildProof(presentation, wallet, element,
          challenge: challenge, proofPurpose: 'authentication'));
    }
  }

  presentation['proof'] = proofList;

  return jsonEncode(presentation);
}

/// Verifies the [presentation].
///
/// It uses erc1056 to look up the current owner of the dids a proof is given in [presentation].
Future<bool> verifyPresentation(dynamic presentation, String challenge,
    {Erc1056? erc1056,
    RevocationRegistry? revocationRegistry,
    Signer? signer,
    Signer Function(
            String typeMatch,
            Function(Uri url, LoadDocumentOptions? options)
                loadDocumentFunction)
        signerSelector = _determineSignerForType,
    Function(Uri url, LoadDocumentOptions? options) loadDocumentFunction =
        loadDocumentStrict}) async {
  // datatype conversion
  Map<String, dynamic> presentationMap;
  if (presentation is VerifiablePresentation) {
    presentationMap = presentation.toJson();
  } else {
    presentationMap = credentialToMap(presentation);
  }

  // get proof(s) as List
  var proofs = presentationMap['proof'];
  if (proofs is Map<String, dynamic>) {
    proofs = [proofs];
  }
  proofs as List;
  presentationMap.remove('proof');

  // verify credentials
  var credentials = presentationMap['verifiableCredential'] as List;
  List<String> holderDids = [];
  await Future.forEach(credentials, (dynamic element) async {
    bool verified = await verifyCredential(element,
        erc1056: erc1056,
        revocationRegistry: revocationRegistry,
        signerSelector: signerSelector,
        loadDocumentFunction: loadDocumentFunction);
    if (!verified) {
      throw Exception('A credential could not been verified');
    } else {
      var did = getHolderDidFromCredential(element);
      if (erc1056 != null) did = await erc1056.identityOwner(did);
      if (did.isNotEmpty && did.startsWith('did:')) {
        holderDids.add(did);
      }
    }
  });

  // check for holder property
  if (presentationMap.containsKey('holder')) {
    var holder = presentationMap['holder'];
    if (holder is String && holder.startsWith('did:')) {
      holderDids.add(holder);
    }
  }

  // verify proofs from presentation
  await Future.forEach(proofs, (dynamic element) async {
    String verifMeth = element['verificationMethod'];
    if (verifMeth.contains('#')) verifMeth = verifMeth.split('#').first;
    if (erc1056 != null) verifMeth = await erc1056.identityOwner(verifMeth);
    var signer = signerSelector.call(element['type'], loadDocumentFunction);
    if (holderDids.contains(verifMeth)) holderDids.remove(verifMeth);
    if (!await signer.verifyProof(element, presentationMap, verifMeth,
        challenge: challenge)) {
      throw Exception('Proof for $verifMeth could not been verified');
    }
  });
  if (holderDids.isNotEmpty) throw Exception('There are dids without a proof');

  presentationMap['proof'] = (proofs.length == 1) ? proofs.first : proofs;

  // compare plaintext credentials (if given)
  if (presentationMap.containsKey('disclosedCredentials')) {
    var disclosedCredentials = presentationMap['disclosedCredentials'] as List;
    Map<String?, Map<String, dynamic>> credsToId = {};
    for (var element in credentials) {
      var did = getHolderDidFromCredential(element);
      credsToId[did] = element;
    }

    for (var element in disclosedCredentials) {
      compareW3cCredentialAndPlaintext(credsToId[element['id']], element);
    }
  }
  return true;
}

///Discloses all values in [valuesToDisclose] of [plaintextCredential].
///
/// [valuesToDisclose] contains the keys of the attributes, that should be disclosed.
/// Keys in nested object should be separated with . (point) from the parent-key, like here:
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
/// ```dart
/// discloseValues(
/// plaintextCredential,
/// [issuanceDate,
///   student.givenName,
///   student.address.addressLocality,
///   student.address.streetAddress
///  ])
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
          result.remove(key);
        }
      }
      // new Object found
      else if (_mapOfHashedAttributesSchema.validate(value)) {
        List<String> valuesSeen = [];
        List<String> valuesToDiscloseNew = [];
        //search in valuesToDisclose if sth. starts with key
        for (var element in valuesToDisclose) {
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
        }
        var newValue = jsonDecode(discloseValues(value, valuesToDiscloseNew));
        result[key] = newValue;
      }
      // array found
      else if (value is List) {
        result[key] = value;
        int removed = 0;
        List<String> valuesSeen = [];
        for (var element in valuesToDisclose) {
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
            if (_hashedAttributeSchemaStrict
                .validate(value[arrayIndex - removed])) {
              result[key].removeAt(arrayIndex - removed);
              removed++;
            }
            //Object in Array
            else if (_mapOfHashedAttributesSchema.validate(value[arrayIndex])) {
              //search in given keys, if sth. else should be disclosed
              List<String> valuesToDiscloseNew = [];
              for (var element in valuesToDisclose) {
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
              }
              result[key][arrayIndex] = jsonDecode(
                  discloseValues(value[arrayIndex], valuesToDiscloseNew));
            } else {
              throw Exception(
                  'Malformed array element in array with key $key at index $arrayIndex');
            }
          }
        }
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
      if (value is String || value is num || value is bool) {
        paths.add(key);
      } else if (value is Map) {
        var objectPaths = getAllJsonPathsOfCredential(value);
        for (var element in objectPaths) {
          paths.add('$key.$element');
        }
      } else if (value is List) {
        for (int i = 0; i < value.length; i++) {
          if (value[i] is String || value[i] is num || value[i] is bool) {
            paths.add('$key.$i');
          } else if (value[i] is Map) {
            var objectPaths = getAllJsonPathsOfCredential(value[i]);
            for (var element in objectPaths) {
              paths.add('$key.$i.$element');
            }
          } else {
            throw Exception(
                'Malformed array element in array with key $key at index $i');
          }
        }
      } else {
        throw Exception('Unknown data type at key $key');
      }
    }
  });

  return paths;
}

/// Build a Presentation definition to e.g. propose the given [credential] for presentation.
PresentationDefinition buildPresentationDefinitionForCredential(
    dynamic credential) {
  VerifiableCredential cred;
  if (credential is VerifiableCredential) {
    cred = credential;
  } else {
    cred = VerifiableCredential.fromJson(credential);
  }

  List<InputDescriptorField> fields = [];

  var type = cred.type.firstWhere(
      (element) => element != 'VerifiableCredential',
      orElse: () => '');
  if (type.isNotEmpty) {
    var typeField = InputDescriptorField(
        path: [JsonPath(r'$.type')],
        filter: JsonSchema.createSchema({
          'type': 'array',
          'contains': {'type': 'string', 'pattern': type}
        }));
    fields.add(typeField);
  }

  var vcAsJson = cred.toJson();

  var paths = getAllJsonPathsOfCredential(vcAsJson);

  for (var path in paths) {
    var asJsonPath = JsonPath('\$.credentialSubject.$path');
    var value = asJsonPath.read(vcAsJson).first.value;
    var field = InputDescriptorField(path: [JsonPath('\$..$path')]);
    if (value is String) {
      field.filter =
          JsonSchema.createSchema({'type': 'string', 'pattern': value});
    } else if (value is num) {
      field.filter = JsonSchema.createSchema({'type': 'number'});
    } else if (value is bool) {
      field.filter = JsonSchema.createSchema({'type': 'boolean'});
    }
    fields.add(field);
  }

  return PresentationDefinition(inputDescriptors: [
    InputDescriptor(constraints: InputDescriptorConstraints(fields: fields))
  ]);
}

String buildJwsHeader(
    {required String alg,
    String? jku,
    Map<String, dynamic>? jwk,
    String? kid,
    String? x5u,
    List<String>? x5c,
    String? x5t,
    String? x5tS256,
    String? typ,
    Map<String, dynamic>? extra}) {
  Map<String, dynamic> jsonObject = {};

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
  Map<String, dynamic> credentialMap;
  if (credential is VerifiableCredential) {
    credentialMap = credential.toJson();
  } else {
    credentialMap = credentialToMap(credential);
  }

  if (!credentialMap.containsKey('issuer')) {
    return '';
  } else {
    var issuer = credentialMap['issuer'];
    if (issuer is String) {
      return issuer;
    } else {
      if (issuer is! Map) {
        return '';
      } else {
        var id = issuer['id'];
        if (id != null) {
          return id;
        } else {
          return '';
        }
      }
    }
  }
}

/// Collects the did of the Holder of [credential].
String getHolderDidFromCredential(dynamic credential) {
  var credMap = credentialToMap(credential);
  if (credMap.containsKey('credentialSubject')) {
    if (credMap['credentialSubject'].containsKey('id')) {
      return credMap['credentialSubject']['id'];
    } else {
      return '';
    }
  } else if (credMap.containsKey('id')) {
    return credMap['id'];
  } else {
    return '';
  }
}

/// Signs the given String (normal or Json-Object) or Json-Object (Dart Map<String, dynamic>) [toSign] with key-pair of [didToSignWith].
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
/// if did is of type did:ethr or
/// ```
/// {
///   "alg" : "EdDSA",
///   "crv" : "Ed25519"
/// }
/// ```
/// if did is of type did:key with appropriate key-Material
/// If a custom one should be used, it has to be given in its json representation (dart String or Map) and the value of alg has to be ES256K-R or EdDSA with curve Ed25519,
/// because for now this is the only supported signature algorithm.
Future<String> signStringOrJson(
    WalletStore wallet, String didToSignWith, dynamic toSign,
    {Signer? signer, bool detached = false, dynamic jwsHeader}) async {
  signer ??= _determineSignerForDid(didToSignWith, null);
  return signer.sign(toSign, wallet, didToSignWith,
      detached: detached, jwsHeader: jwsHeader);
}

/// Extracts the did used for signing [jws].
///
/// If a detached jws is given the signed string must be given separately as [toSign].
/// [toSign] could be a String or a json-object (Dart Map).
Future<String> getDidFromSignature(String jws,
    {String? toSign, Erc1056? erc1056}) async {
  var splitted = jws.split('.');
  if (splitted.length != 3) throw Exception('Malformed JWS');
  var signature = _getSignatureFromJws(jws);
  String payload;
  if (splitted[1] != '') {
    payload = splitted[1];
  } else if (toSign != null) {
    payload = removePaddingFromBase64(base64UrlEncode(utf8.encode(toSign)));
  } else {
    throw Exception('No payload given');
  }
  var signingInput = '${splitted[0]}.$payload';
  var hashToSign = sha256.convert(ascii.encode(signingInput)).bytes;
  var pubKey = ecRecover(hashToSign as Uint8List, signature);

  var did = 'did:ethr:${EthereumAddress.fromPublicKey(pubKey).hexEip55}';
  if (erc1056 != null) {
    if (erc1056.networkName != 'mainnet') {
      did =
          'did:ethr:${erc1056.networkName}:${EthereumAddress.fromPublicKey(pubKey).hexEip55}';
    }
    var expectedDid = await erc1056.identityOwner(did);
    if (expectedDid != did) {
      throw Exception('Did of Signature do not match with ERC1056 entry');
    }
  }
  return did;
}

/// Verifies the signature in [jws].
///
/// If a detached jws is given the signed string must be given separately as [toSign].
/// [toSign] could be a String or a json-object (Dart Map).
Future<bool> verifyStringSignature(String jws, String expectedDid,
    {dynamic toSign, Erc1056? erc1056}) async {
  var signer = _determineSignerForDid(expectedDid, null);
  if (expectedDid.startsWith('did:ethr') && erc1056 != null) {
    expectedDid = await erc1056.identityOwner(expectedDid);
  }

  return signer.verify(jws, expectedDid, data: toSign);
}

List<FilterResult> searchCredentialsForPresentationDefinition(
    List<dynamic> credentials, PresentationDefinition presentationDefinition) {
  var creds = <VerifiableCredential>[];
  for (var entry in credentials) {
    if (entry is VerifiableCredential) {
      creds.add(entry);
    } else {
      creds.add(VerifiableCredential.fromJson(entry));
    }
  }

  var globalFormat = presentationDefinition.format;
  if (globalFormat != null) {
    if (globalFormat.ldpVp == null &&
        globalFormat.ldp == null &&
        globalFormat.ldpVc == null) {
      throw Exception('Only supported Formats are Linked Data proofs');
    }
  }

  if (presentationDefinition.submissionRequirement != null) {
    Map<String, FilterResult> filterResultPerDescriptor = {};
    Map<String, dynamic> descriptorGroups = {};

    //search things for all descriptors
    for (var descriptor in presentationDefinition.inputDescriptors) {
      if (descriptor.group == null) {
        throw Exception('Ungrouped input descriptor');
      }

      //input descriptors per group
      for (var g in descriptor.group!) {
        if (descriptorGroups.containsKey(g)) {
          List<dynamic> gl = descriptorGroups[g];
          gl.add(descriptor.id);
          descriptorGroups[g] = gl;
        } else {
          descriptorGroups[g] = [descriptor.id];
        }
      }

      //credentials per descriptor
      var filteredCreds =
          _processInputDescriptor(descriptor, globalFormat, creds);
      filterResultPerDescriptor[descriptor.id] = filteredCreds;
    }
    //Evaluate submission requirements
    List<FilterResult> finalCredList = [];
    for (var requirement in presentationDefinition.submissionRequirement!) {
      finalCredList.add(_processSubmissionRequirement(filterResultPerDescriptor,
          descriptorGroups, requirement, presentationDefinition.id));
    }
    return finalCredList;
  } else {
    List<VerifiableCredential> inputCreds = creds;
    List<String> allDescriptorIds = [];
    List<InputDescriptorConstraints> allSelfIssuables = [];
    for (var descriptor in presentationDefinition.inputDescriptors) {
      //Without any requirements, all input_descriptors must be fulfilled
      allDescriptorIds.add(descriptor.id);
      var res = _processInputDescriptor(descriptor, globalFormat, inputCreds);
      inputCreds = res.credentials;
      if (res.selfIssuable != null) {
        allSelfIssuables.addAll(res.selfIssuable!);
      }
    }
    return [
      FilterResult(
          selfIssuable: allSelfIssuables.isNotEmpty ? allSelfIssuables : null,
          credentials: inputCreds,
          matchingDescriptorIds: allDescriptorIds,
          presentationDefinitionId: presentationDefinition.id)
    ];
  }
}

FilterResult _processSubmissionRequirement(
    Map<String, FilterResult> filterResultPerDescriptor,
    Map<String, dynamic> descriptorGroups,
    SubmissionRequirement requirement,
    String definitionId) {
  if (requirement.fromNested != null) {
    //for (var nestedRequirement in requirement.fromNested!) {}
    //TODO:process path nested in submission requirement
    throw UnimplementedError('Cant process from nested entries yet');
  }

  List<String> accordingDescriptors = descriptorGroups[requirement.from];
  List<VerifiableCredential> creds = [];
  List<InputDescriptorConstraints> selfIssuable = [];

  for (String d in accordingDescriptors) {
    var descriptor = filterResultPerDescriptor[d]!;
    if (descriptor.selfIssuable != null) {
      selfIssuable.addAll(descriptor.selfIssuable!);
    }
    var credsForDescriptor = descriptor.credentials;
    if (requirement.rule == SubmissionRequirementRule.all) {
      if (credsForDescriptor.isEmpty && descriptor.selfIssuable == null) {
        throw Exception('Can\'t fulfill submission requirement');
      }
    }
    if (creds.isEmpty) {
      creds = credsForDescriptor;
    } else {
      List<VerifiableCredential> toAdd = [];
      for (var c1 in creds) {
        for (var c2 in credsForDescriptor) {
          //TODO find better criteria to compare
          if (c1.id != c2.id) toAdd.add(c2);
        }
      }
      creds += toAdd;
    }
  }

  if (requirement.rule == SubmissionRequirementRule.pick) {
    int notLower = 0;
    if (requirement.count != null) notLower = requirement.count!;
    if (requirement.min != null) notLower = requirement.min!;
    if (creds.length < notLower && selfIssuable.isEmpty) {
      throw Exception('Could not fullfill submission requirement');
    }
  }

  return FilterResult(
      selfIssuable: selfIssuable.isNotEmpty ? selfIssuable : null,
      credentials: creds,
      matchingDescriptorIds: accordingDescriptors,
      submissionRequirement: requirement,
      presentationDefinitionId: definitionId);
}

FilterResult _processInputDescriptor(InputDescriptor descriptor,
    FormatProperty? globalFormat, List<VerifiableCredential> creds) {
  var localFormat = globalFormat;
  if (descriptor.format != null) {
    if (descriptor.format != null) {
      if (descriptor.format!.ldpVp == null &&
          descriptor.format!.ldp == null &&
          descriptor.format!.ldpVc == null) {
        throw Exception('Only supported Formats are Linked Data proofs');
      }
    } else {
      localFormat = descriptor.format;
    }
  }

  List<VerifiableCredential> candidate = [];
  if (descriptor.constraints != null) {
    if (descriptor.constraints!.isHolder != null) {
      throw UnimplementedError('is_holder property is not supported yet');
    }
    if (descriptor.constraints!.sameSubject != null) {
      throw UnimplementedError('same_subject feature is not supported yet');
    }
    if (descriptor.constraints!.statuses != null) {
      throw UnimplementedError('statuses feature is not supported yet');
    }
    // if (descriptor.constraints!.subjectIsIssuer != null) {
    //   if (descriptor.constraints!.subjectIsIssuer! == Limiting.required) {
    //     return FilterResult(
    //         credentials: [],
    //         matchingDescriptorIds: [descriptor.id],
    //         presentationDefinitionId: '',
    //         selfIssuable: [descriptor.constraints!]);
    //   }
    // }

    if (descriptor.constraints!.fields != null) {
      var fields = descriptor.constraints!.fields!;
      for (var cred in creds) {
        if (descriptor.constraints!.subjectIsIssuer != null &&
            descriptor.constraints!.subjectIsIssuer! == Limiting.required) {
          if (!cred.isSelfIssued()) continue;
        }
        Set<bool> isCandidateSet = {};
        for (var field in fields) {
          if (field.predicate != null) {
            throw UnimplementedError(
                'Evaluating predicate feature is not supported yet');
          }
          bool pathMatch = false;
          for (var path in field.path) {
            var match = path.read(cred.toJson());
            var matchList = match.toList();
            if (matchList.isEmpty &&
                (field.optional == null || field.optional == false)) continue;
            if (field.filter != null) {
              if (field.filter!.validate(matchList[0].value) &&
                  (field.optional == null || field.optional == false)) {
                pathMatch = true;
              }
            } else {
              pathMatch = true;
            }
          }
          isCandidateSet.add(pathMatch);
        }
        if (isCandidateSet.length == 1 && isCandidateSet.first) {
          candidate.add(cred);
        }
      }
    }
  }

  //check against format
  if (localFormat != null) {
    List<VerifiableCredential> candidateFormatFiltered = [];
    for (var cred in candidate) {
      String credProofFormat = cred.proof!.type;
      if (localFormat.ldpVc != null) {
        if (localFormat.ldpVc!.proofType.contains(credProofFormat)) {
          candidateFormatFiltered.add(cred);
        }
      }
    }
    return FilterResult(
        selfIssuable: descriptor.constraints?.subjectIsIssuer != null
            ? [descriptor.constraints!]
            : null,
        credentials: candidateFormatFiltered,
        matchingDescriptorIds: [descriptor.id],
        presentationDefinitionId: '');
  }
  return FilterResult(
      selfIssuable: descriptor.constraints?.subjectIsIssuer != null
          ? [descriptor.constraints!]
          : null,
      credentials: candidate,
      matchingDescriptorIds: [descriptor.id],
      presentationDefinitionId: '');
}

//***********************Private Methods***************************************

Map<String, dynamic> _hashStringOrNum(dynamic value) {
  var uuid = Uuid();
  Map<String, dynamic> hashed = {};
  var salt = uuid.v4();
  hashed.putIfAbsent('value', () => value);
  hashed.putIfAbsent('salt', () => salt);
  return hashed;
}

String _collectHashes(dynamic credential,
    {String? id, bool firstLevel = false}) {
  var credMap = credentialToMap(credential);
  Map<String, dynamic> hashCred = {};
  if (id != null) hashCred['id'] = id;
  credMap.forEach((key, value) {
    if (key != '@context') {
      if (key == 'type' || key == '@type') {
        hashCred[key] = value;
      } else if (key == 'id' && firstLevel) {
        hashCred[key] = value;
      } else if (key == 'hashAlg') {
      } else if (value is List) {
        List<dynamic> hashList = [];
        for (var element in value) {
          if (element is Map<String, dynamic> &&
              _hashedAttributeSchema.validate(element)) {
            hashList.add(bytesToHex(
                keccakUtf8('${element['salt']}${element['value']}'),
                include0x: true));
          } else if (element is Map<String, dynamic> &&
              _mapOfHashedAttributesSchema.validate(element)) {
            hashList.add(jsonDecode(_collectHashes(element)));
          } else {
            throw Exception('unknown type  with key $key');
          }
          hashCred[key] = hashList;
        }
      } else if (value is Map<String, dynamic> &&
          _hashedAttributeSchema.validate(value)) {
        hashCred[key] = bytesToHex(
            keccakUtf8('${value['salt']}${value['value']}'),
            include0x: true);
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
      if (value is Map<String, dynamic>) {
        if (_hashedAttributeSchemaStrict.validate(value)) {
          //a disclosed value -> rehash and check
          var hash = bytesToHex(
              keccakUtf8(value['salt'] + value['value'].toString()),
              include0x: true);
          if (hash != w3c[key]) {
            throw Exception(
                'Given hash and calculated hash do ot match at $key');
          }
        } else if (_mapOfHashedAttributesSchema.validate(value) &&
            _mapOfHashedAttributesSchema.validate(w3c[key])) {
          // a new Object
          _checkHashes(w3c[key], value);
        } else if (value.length == 1) {
          throw Exception('malformed object with key $key');
        }
      } else if (value is List) {
        List<dynamic> fromW3c = w3c[key];
        for (int i = 0; i < value.length; i++) {
          if (value[i] is Map<String, dynamic> &&
              _hashedAttributeSchemaStrict.validate(value[i])) {
            // a disclosed value -> rehash and check
            var hash = bytesToHex(
                keccakUtf8(value[i]['salt'] + value[i]['value'].toString()),
                include0x: true);
            if (!fromW3c.contains(hash)) {
              throw Exception(
                  'Calculated and given Hash in List at $key do not match');
            }
          } else if (value[i] is Map<String, dynamic> &&
              _mapOfHashedAttributesSchema.validate(value[i])) {
            if (value[i].length > 0) _checkHashes(fromW3c[i], value[i]);
          } else {
            throw Exception('unknown datatype at List $key and index $i');
          }
        }
      } else {
        throw Exception('unknown datatype with key $key');
      }
    }
  });
  return true;
}

Map<String, dynamic> mergeSdJwt(String sdJwt) {
  Map<String, dynamic> merged = {};
  var split = sdJwt.split('.');
  if (split.length != 3) {
    throw Exception('JWT consists of 3 parts');
  }

  var sig = split.last;
  var disclosures = sig.split('~');
  disclosures.removeAt(0);

  Map<String, Disclosure> disclosureMap = {};

  Map<String, dynamic> payload = jsonDecode(split[1]);
  var hashAlg = payload['_sd_hash_alg'];
  if (hashAlg != 'sha-256') {
    throw UnimplementedError('Only sha-256 hashing is supported');
  }

  for (var d in disclosures) {
    var hash = sha256.convert(ascii.encode(d));
    disclosureMap[base64UrlEncode(hash.bytes)] = Disclosure.fromBase64(d);
  }

  return merged;
}

Map<String, dynamic> _mergeSd(
    Map<String, dynamic> payload, Map<String, Disclosure> disclosures) {
  Map<String, dynamic> merged = {};
  payload.forEach((key, value) {
    if (key != '_sd' || (value is Map && value.containsKey('_sd'))) {
      merged[key] = value;
    } else {
      if (key == '_sd') {
      } else {
        merged[key] = _mergeSd(value, disclosures);
      }
    }
  });

  return merged;
}

class Disclosure {
  String salt;
  String propertyName;
  String base64;
  dynamic value;

  Disclosure(
      {required this.salt,
      required this.value,
      required this.base64,
      required this.propertyName});

  factory Disclosure.fromBase64(String disclosure) {
    List dis = jsonDecode(utf8.decode(base64Decode(disclosure)));

    return Disclosure(
        salt: dis.first,
        value: dis.last,
        base64: disclosure,
        propertyName: dis[1]);
  }
}

String buildProofOptions(
    {required SignatureType type,
    required String verificationMethod,
    String? domain,
    String? challenge}) {
  Map<String, dynamic> jsonObject = {};
  jsonObject.putIfAbsent('type', () => type.value);
  jsonObject.putIfAbsent('proofPurpose', () => 'assertionMethod');
  jsonObject.putIfAbsent('verificationMethod', () => verificationMethod);
  jsonObject.putIfAbsent(
      'created', () => DateTime.now().toUtc().toIso8601String());

  if (domain != null) {
    jsonObject['domain'] = domain;
  }

  if (challenge != null) {
    jsonObject['challenge'] = challenge;
  }
  return json.encode(jsonObject);
}

enum SignatureType {
  ecdsaRecovery,
  edDsa;

  static const Map<SignatureType, String> stringValues = {
    SignatureType.ecdsaRecovery: 'EcdsaSecp256k1RecoverySignature2020',
    SignatureType.edDsa: 'Ed25519Signature2020',
  };
  String get value => stringValues[this]!;
}

MsgSignature _getSignatureFromJws(String jws) {
  var splitJws = jws.split('.');
  Map<String, dynamic> header =
      jsonDecode(utf8.decode(base64Decode(addPaddingToBase64(splitJws[0]))));
  if (header['alg'] != 'ES256K-R') {
    throw Exception('Unsupported signature Algorithm ${header['alg']}');
  }
  var sigArray = base64Decode(addPaddingToBase64(splitJws[2]));
  if (sigArray.length != 65) throw Exception('wrong signature-length');
  return MsgSignature(bytesToUnsignedInt(sigArray.sublist(0, 32)),
      bytesToUnsignedInt(sigArray.sublist(32, 64)), sigArray[64] + 27);
}
