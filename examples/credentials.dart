import 'dart:convert';

import 'package:flutter_ssi_wallet/flutter_ssi_wallet.dart';

void main() async {
  WalletStore w = new WalletStore('testWallet');
  await w.openBoxes('myPassword');
  var issuerDid = await w.initializeIssuer();
  //build example-credential
  Map<String, dynamic> credential = new Map();
  List<String> contexts = new List();
  contexts.add('https://www.w3.org/2018/credentials/v1');
  contexts.add('https://hs-mittweida.de/ldContext/imma');
  credential.putIfAbsent('@context', () => contexts);
  credential.putIfAbsent('id', () => 'did:ethr:1234567');
  credential.putIfAbsent('type', () => 'Immatrikulation');
  var issuer = new Map<String, dynamic>();
  issuer.putIfAbsent('id', () => issuerDid);
  issuer.putIfAbsent('name', () => 'Hochschule Mittweida');
  credential.putIfAbsent('issuer', () => issuer);
  credential.putIfAbsent(
      'issuanceDate', () => DateTime.now().toIso8601String());
  var subject = new Map<String, dynamic>();
  subject.putIfAbsent('id', () => 'did:ethr:1234567');
  subject.putIfAbsent('courseOfStudies', () => 'Cybercrime');
  credential.putIfAbsent('credentialSubject', () => subject);

  var credString = jsonEncode(credential);
  print(credString);

  var signedCredential = signCredential(w, credString);
  print(signedCredential);

  print(verifyCredential(signedCredential));
}
