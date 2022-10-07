import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:base_codecs/base_codecs.dart';
import 'package:web3dart/crypto.dart';

import '../credentials/credential_operations.dart';

Uint8List _multibaseToUint8List(String multibase) {
  if (multibase.startsWith('z')) {
    return base58BitcoinDecode(multibase.substring(1));
  } else {
    throw UnimplementedError('Unsupported multibase indicator ${multibase[0]}');
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
    throw Exception('unknown type for $credential');
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
    var client = await HttpClient()
        .getUrl(Uri.parse('https://${uri.host}/.well-known/did-configuration'))
        .timeout(Duration(seconds: 30));
    var res = await client.close();
    if (res.statusCode == 200) {
      var contents = StringBuffer();
      await for (var data in res.transform(utf8.decoder)) {
        contents.write(data);
      }
      var entries = jsonDecode(contents.toString());
      List<dynamic> dids = entries['entries'];
      await Future.forEach(dids, (dynamic element) async {
        var jwt = element['jwt'];
        var did = element['did'];
        print(did);
        var verified = await verifyStringSignature(jwt, did);
        print(verified);
        if (verified) didsInConfig.add(did);
      });
    }
  } catch (e) {
    throw Exception('Error occurred during fetch of did-configuration: $e');
  }
  return didsInConfig;
}

/// Request TLS Certificate of [url] and extract important information from it.
Future<CertificateInformation?> getCertificateInfoFromUrl(String url) async {
  if (!url.startsWith(RegExp('http.', caseSensitive: false))) {
    url = 'https://$url';
  }
  if (!url.startsWith(RegExp('https', caseSensitive: false))) {
    url = url.replaceAll(RegExp('http', caseSensitive: false), 'https');
  }
  try {
    var client = await HttpClient()
        .getUrl(Uri.parse(url))
        .timeout(Duration(seconds: 30));
    var res = await client.close();
    if (res.certificate == null) {
      return null;
    } else {
      return CertificateInformation(res.certificate, true);
    }
  } catch (e) {
    throw Exception('Error occurred during certificate check: $e');
  }
}

/// Important information of TLS Certificate
class CertificateInformation {
  bool? valid;
  String? subjectCommonName;
  String? subjectOrganization;
  List<String>? subjectAlternativeNames;
  String? issuerOrganization;
  String? issuerCommonName;
  String? issuerCountry;
  X509Certificate? rawCert;
  bool isEvCert = false;

  final List<String> _evOIDs = [
    '2.23.140.1.1',
    '1.2.156.112559.1.1.6.1',
    '2.16.756.5.14.7.4.8',
    '1.2.392.200091.100.721.1',
    '2.16.156.112554.3',
    '2.16.840.1.114028.10.1.2',
    '2.16.840.1.114028.10.1.',
    '2.16.528.1.1003.1.2.7',
    '2.16.840.1.114028.10.1.2',
    '1.3.6.1.4.1.6449.1.2.1.5.1',
    '1.3.6.1.4.1.8024.0.2.100.1.2',
    '2.16.840.1.114412.2.1',
    '1.3.159.1.17.1',
    '2.16.792.3.0.4.1.1.4',
    '1.3.6.1.4.1.40869.1.1.22.3',
    '1.3.6.1.4.1.13177.10.1.3.10',
    '1.3.6.1.4.1.4788.2.202.1',
    '1.3.6.1.4.1.40869.1.1.22.3',
    '1.3.6.1.4.1.7879.13.24.1',
    '1.3.6.1.4.1.14777.6.1.2',
    '1.3.6.1.4.1.14777.6.1.1',
    '1.2.616.1.113527.2.5.1.1',
    '1.3.6.1.4.1.34697.2.4',
    '1.3.6.1.4.1.34697.2.3',
    '1.3.6.1.4.1.34697.2.2',
    '1.3.6.1.4.1.34697.2.1',
    '2.16.578.1.26.1.3.3',
    '2.16.840.1.114028.10.1.2',
    '2.16.840.1.114028.10.1.2',
    '1.3.6.1.4.1.782.1.2.1.8.1',
    '1.3.6.1.4.1.8024.0.2.100.1.2',
    '2.16.840.1.114414.1.7.23.3',
    '1.3.6.1.4.1.6449.1.2.1.5.1',
    '1.3.6.1.4.1.6449.1.2.1.5.1',
    '2.16.840.1.114404.1.1.2.4.1',
    '2.16.756.1.89.1.2.1.1',
    '1.3.6.1.4.1.6334.1.100.1'
  ];

  CertificateInformation(X509Certificate? certificate, bool this.valid) {
    rawCert = certificate;
    var splittedSubject = _splitSubject(rawCert!.subject);
    subjectCommonName = splittedSubject['CN'];
    subjectOrganization = splittedSubject['O'];
    subjectAlternativeNames = _getSubjectAlternativeNames();
    var splittedIssuer = _splitSubject(rawCert!.issuer);
    issuerCommonName = splittedIssuer['CN'];
    issuerOrganization = splittedIssuer['O'];
    issuerCountry = splittedIssuer['C'];
    var extractedEvOids = _extractEvOids();
    if (extractedEvOids.isNotEmpty) {
      for (var element in extractedEvOids) {
        if (_evOIDs.contains(element)) {
          isEvCert = true;
        }
      }
    }
  }

  List<String?> _extractEvOids() {
    List<String?> extracted = [];
    var p = ASN1Parser(rawCert!.der);
    var signedCert = p.nextObject() as ASN1Sequence;
    var cert = signedCert.elements[0] as ASN1Sequence;
    if (cert.elements.length == 8) {
      var extObject = cert.elements[7];
      var extParser = ASN1Parser(extObject.valueBytes());
      var extSeq = extParser.nextObject() as ASN1Sequence;
      for (var element in extSeq.elements) {
        var seq = element as ASN1Sequence;
        var oi = seq.elements[0] as ASN1ObjectIdentifier;
        if (oi.identifier == '2.5.29.32') {
          var policyRaw = seq.elements[1] as ASN1OctetString;
          var policyParser = ASN1Parser(policyRaw.octets);
          var policy = policyParser.nextObject() as ASN1Sequence;
          for (var element in policy.elements) {
            var policy1 = element as ASN1Sequence;
            var policyOID = policy1.elements[0] as ASN1ObjectIdentifier;
            extracted.add(policyOID.identifier);
          }
        }
      }
    }
    return extracted;
  }

  Map<String, String> _splitSubject(String subject) {
    var splitted = subject.split('/');
    Map<String, String> foundElements = {};
    for (var element in splitted) {
      if (element != '') {
        var keyValue = element.split('=');
        foundElements[keyValue[0]] = keyValue[1];
      }
    }

    return foundElements;
  }

  List<String>? _getSubjectAlternativeNames() {
    var parser = ASN1Parser(rawCert!.der);
    var topLevel = parser.nextObject() as ASN1Sequence;
    var dataSequence = topLevel.elements[0] as ASN1Sequence;
    List<String>? sans;
    if (dataSequence.elements.length == 8) {
      var extensionObject = dataSequence.elements[7];
      var extParser = ASN1Parser(extensionObject.valueBytes());
      var extSequence = extParser.nextObject() as ASN1Sequence;

      for (var subseq in extSequence.elements) {
        var seq = subseq as ASN1Sequence;
        var oi = seq.elements[0] as ASN1ObjectIdentifier;
        if (oi.identifier == '2.5.29.17') {
          if (seq.elements.length == 3) {
            sans = _fetchSansFromExtension(seq.elements.elementAt(2));
          } else {
            sans = _fetchSansFromExtension(seq.elements.elementAt(1));
          }
        }
      }
    }
    return sans;
  }

  static List<String> _fetchSansFromExtension(ASN1Object extData) {
    var sans = <String>[];
    var octet = extData as ASN1OctetString;
    var sanParser = ASN1Parser(octet.valueBytes());
    var sanSeq = sanParser.nextObject() as ASN1Sequence;
    for (var san in sanSeq.elements) {
      if (san.tag == 135) {
        var sb = StringBuffer();
        san.valueBytes().forEach((int b) {
          if (sb.isNotEmpty) {
            sb.write('.');
          }
          sb.write(b);
        });
        sans.add(sb.toString());
      } else {
        var s = String.fromCharCodes(san.valueBytes());
        sans.add(s);
      }
    }
    return sans;
  }
}
