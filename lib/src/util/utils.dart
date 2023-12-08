import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:base_codecs/base_codecs.dart';
import 'package:crypto/crypto.dart';
import 'package:dart_multihash/dart_multihash.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:elliptic/elliptic.dart';
import 'package:http/http.dart' as http;
import 'package:web3dart/crypto.dart';

import '../credentials/credential_operations.dart';
import '../wallet/wallet_store.dart';

Uint8List _multibaseToUint8List(String multibase) {
  if (multibase.startsWith('z')) {
    return base58BitcoinDecode(multibase.substring(1));
  } else {
    throw UnimplementedError('Unsupported multibase indicator ${multibase[0]}');
  }
}

bool isUri(String uri) {
  try {
    Uri.parse(uri);
    return true;
  } catch (_) {
    return false;
  }
}

String multibaseToBase64Url(String multibase) {
  return base64UrlEncode(_multibaseToUint8List(multibase));
}

Map<String, dynamic> multibaseKeyToJwk(String multibaseKey) {
  var key = _multibaseToUint8List(multibaseKey);
  var indicator = key.sublist(0, 2);
  var indicatorHex = bytesToHex(indicator);
  key = key.sublist(2);
  Map<String, dynamic> jwk = {};
  if (indicatorHex == 'ed01') {
    jwk['kty'] = 'OKP';
    jwk['crv'] = 'Ed25519';
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(key));
  } else if (indicatorHex == 'ec01') {
    jwk['kty'] = 'OKP';
    jwk['crv'] = 'X25519';
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(key));
  } else if (indicatorHex == '8024') {
    jwk['kty'] = 'EC';
    jwk['crv'] = 'P-256';
    var c = getP256();
    var pub = c.compressedHexToPublicKey(hex.encode(key));
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(
        pub.X < BigInt.zero ? intToBytes(pub.X) : unsignedIntToBytes(pub.X)));
    jwk['y'] = removePaddingFromBase64(base64UrlEncode(
        pub.Y < BigInt.zero ? intToBytes(pub.Y) : unsignedIntToBytes(pub.Y)));
  } else if (indicatorHex == 'e701') {
    jwk['kty'] = 'EC';
    jwk['crv'] = 'secp256k1';
    var c = getSecp256k1();
    var pub = c.compressedHexToPublicKey(hex.encode(key));
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(
        pub.X < BigInt.zero ? intToBytes(pub.X) : unsignedIntToBytes(pub.X)));
    jwk['y'] = removePaddingFromBase64(base64UrlEncode(
        pub.Y < BigInt.zero ? intToBytes(pub.Y) : unsignedIntToBytes(pub.Y)));
  } else if (indicatorHex == '8124') {
    jwk['kty'] = 'EC';
    jwk['crv'] = 'P-384';
    var c = getP384();
    var pub = c.compressedHexToPublicKey(hex.encode(key));
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(
        pub.X < BigInt.zero ? intToBytes(pub.X) : unsignedIntToBytes(pub.X)));
    jwk['y'] = removePaddingFromBase64(base64UrlEncode(
        pub.Y < BigInt.zero ? intToBytes(pub.Y) : unsignedIntToBytes(pub.Y)));
  } else if (indicatorHex == '8224') {
    jwk['kty'] = 'EC';
    jwk['crv'] = 'P-521';
    var c = getP521();
    var pub = c.compressedHexToPublicKey(hex.encode(key));
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(
        pub.X < BigInt.zero ? intToBytes(pub.X) : unsignedIntToBytes(pub.X)));
    jwk['y'] = removePaddingFromBase64(base64UrlEncode(
        pub.Y < BigInt.zero ? intToBytes(pub.Y) : unsignedIntToBytes(pub.Y)));
  } else {
    throw UnimplementedError(
        'Unsupported multicodec indicator 0x$indicatorHex');
  }
  return jwk;
}

/// Converts json-String [credential] to dart Map.
Map<String, dynamic> credentialToMap(dynamic credential) {
  if (credential is String) {
    return jsonDecode(credential);
  } else if (credential is Map<String, dynamic>) {
    return credential;
  } else {
    throw Exception(
        'Unknown datatype ${credential.runtimeType} for $credential. Only String or Map<String, dynamic> accepted');
  }
}

String addPaddingToBase64(String base64Input) {
  while (base64Input.length % 4 != 0) {
    base64Input += '=';
  }
  return base64Input;
}

String removePaddingFromBase64(String base64Input) {
  while (base64Input.endsWith('=')) {
    base64Input = base64Input.substring(0, base64Input.length - 1);
  }
  return base64Input;
}

Future<List<String>> getDidFromDidConfiguration(String url) async {
  List<String> didsInConfig = [];
  var uri = Uri.parse(url);
  print('https://${uri.host}/.well-known/did-configuration');
  try {
    var res = await http
        .get(Uri.parse('https://${uri.host}/.well-known/did-configuration'))
        .timeout(Duration(seconds: 30));
    if (res.statusCode == 200) {
      var entries = jsonDecode(res.body);
      List<dynamic> dids = entries['entries'];
      await Future.forEach(dids, (dynamic element) async {
        var jwt = element['jwt'];
        var did = element['did'];
        print(did);
        var verified = await verifyStringSignature(jwt, expectedDid: did);
        print(verified);
        if (verified) didsInConfig.add(did);
      });
    }
  } catch (e) {
    throw Exception('Error occurred during fetch of did-configuration: $e');
  }
  return didsInConfig;
}

ASN1Set _buildSubjectInfoPart(String part, String data) {
  var set = ASN1Set();
  var seq = ASN1Sequence();
  List<int> oid = [2, 5, 4];
  switch (part) {
    case 'commonName':
      oid.add(3);
      break;
    case 'stateOrProvinceName':
      oid.add(8);
      break;
    case 'localityName':
      oid.add(7);
      break;
    case 'organizationName':
      oid.add(10);
      break;
    case 'organizationalUnitName':
      oid.add(11);
      break;
  }
  seq.add(ASN1ObjectIdentifier(oid, identifier: part));
  seq.add(ASN1UTF8String(data));
  set.add(seq);
  return set;
}

/// Generate a x509 Certificate Signing Request for a key belonging to [did].
Future<String> buildCsrForDid(WalletStore wallet, String did,
    {String? countryCode,
    String? state,
    String? city,
    String? organization,
    String? organizationalUnit,
    String? emailAddress}) async {
  if (!did.startsWith('did:key:z6Mk')) {
    throw Exception('Only did:key with Ed25519 keys are supported now');
  }

  String? privateKey;
  privateKey = await wallet.getPrivateKeyForCredentialDid(did);
  privateKey ??= await wallet.getPrivateKeyForConnectionDid(did);
  if (privateKey == null) {
    throw Exception('Could not find private Key for DID $did');
  }

  var key = ed.PrivateKey(hexToBytes(privateKey).toList());
  var pub = ed.public(key);

  var csr = ASN1Sequence();
  var cri = ASN1Sequence();

  //Version
  cri.add(ASN1Integer(BigInt.zero));

  //subject
  var subject = ASN1Sequence();

  //countryCode in subject
  if (countryCode != null) {
    if (countryCode.length != 2) {
      throw Exception('Only two letter countryCodes are accepted');
    }
    var country = ASN1Sequence();
    country.add(ASN1ObjectIdentifier([2, 5, 4, 6], identifier: 'countryName'));
    country.add(ASN1PrintableString(countryCode));
    var countrySet = ASN1Set();
    countrySet.add(country);
    subject.add(countrySet);
  }

  if (state != null) {
    subject.add(_buildSubjectInfoPart('stateOrProvinceName', state));
  }
  if (city != null) {
    subject.add(_buildSubjectInfoPart('localityName', city));
  }
  if (organization != null) {
    subject.add(_buildSubjectInfoPart('organizationName', organization));
  }
  if (organizationalUnit != null) {
    subject.add(
        _buildSubjectInfoPart('organizationalUnitName', organizationalUnit));
  }

  subject.add(_buildSubjectInfoPart('commonName', did));

  //email
  if (emailAddress != null) {
    var country = ASN1Sequence();
    country.add(ASN1ObjectIdentifier([1, 2, 840, 113549, 1, 9, 1],
        identifier: 'countryName'));
    country.add(ASN1IA5String(emailAddress));
    var countrySet = ASN1Set();
    countrySet.add(country);
    subject.add(countrySet);
  }

  //subject public Key
  var publicKey = ASN1Sequence();
  var pubKeyId = ASN1Sequence();
  pubKeyId.add(ASN1ObjectIdentifier([1, 3, 101, 112]));
  publicKey.add(pubKeyId);
  publicKey.add(ASN1BitString(pub.bytes));
  var sigId = ASN1Sequence()..add(ASN1ObjectIdentifier([1, 3, 101, 112]));

  //build together Certificate Request Info
  cri.add(subject);
  cri.add(publicKey);

  //sign
  var sig = ed.sign(ed.PrivateKey(hexToBytes(privateKey).toList()),
      Uint8List.fromList(cri.encodedBytes));
  csr.add(cri);
  csr.add(sigId);
  csr.add(ASN1BitString(sig));

  //buildPem
  var buffer = StringBuffer();
  var bytes = csr.encodedBytes;
  buffer.writeln('-----BEGIN CERTIFICATE REQUEST-----');
  for (var i = 0; i < bytes.length; i += 48) {
    buffer.writeln(base64.encode(bytes.skip(i).take(48).toList()));
  }
  buffer.writeln('-----END CERTIFICATE REQUEST-----');
  return buffer.toString();
}

/// Checks multihash format
/// only supporting sha2-256 atm.
bool checkMultiHash(Uint8List hash, Uint8List data) {
  var multihash = Multihash.decode(hash);
  if (multihash.code != 0x12) {
    throw Exception("Hash function must be "
        "sha2-256 for now (Code: 34893)");
  }

  var hashedData = sha256.convert(data).bytes;
  for (var i = 0; i < hashedData.length; i++) {
    var a = multihash.digest[i];
    var b = hashedData[i];
    if (a != b) {
      return false;
    }
  }
  return hashedData.length == multihash.digest.length;
}

String getDateTimeNowString() {
  var date = DateTime.now();
  var asString = date.toUtc().toIso8601String();
  var xmlDate = asString.split('.').first;
  xmlDate += 'Z';
  return xmlDate;
}
