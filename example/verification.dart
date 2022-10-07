import 'dart:convert';
import 'dart:io';

import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/did.dart';
import 'package:dart_ssi/wallet.dart';
import 'package:uuid/uuid.dart';

//This example shows how holder and verifier could interact.
//You should run the example issuance.dart before to make sure, the credential exists.

main() async {
  const String rpcUrl = 'http://127.0.0.1:7545';
  var erc1056 = Erc1056(rpcUrl,
      contractAddress: '0x0eE301c92471234038E320153A7F650ab9a72e28');
  var revocationRegistry = RevocationRegistry(rpcUrl);

  //init Holder Wallet
  var holder = WalletStore('exampleData/holder');
  await holder.openBoxes('holderPW');

  //Verifier generates nonce/challenge for this presentation
  // and sends it to holder
  var challenge = Uuid().v4();

  //Holder searches credential in Wallet and builds a Presentation with the W3C-Credential
  var allCredentials = holder.getAllCredentials();
  var keyList = allCredentials.keys;
  Credential c = allCredentials[keyList.first]!;
  var presentation =
      await buildPresentation([c.w3cCredential], holder, challenge);
  await File('exampleData/presentation.json').writeAsString(presentation);

  //Holder hides all values he wouldn't show
  Map<String, dynamic> plaintext = jsonDecode(c.plaintextCredential);
  print(plaintext.containsKey('student'));
  var plaintextDis = discloseValues(c.plaintextCredential, [
    'issuanceDate',
    'student.givenName',
    'student.address',
    'student.familyName',
    'student.birthPlace',
    'student.birthDate',
    'immatrikulation'
  ]);
  await File('exampleData/disclosedImma.json').writeAsString(plaintextDis);

  //Holder sends both to verifier

  //Holder stores History of Exchanges
  await holder.storeExchangeHistoryEntry(
      keyList.first,
      DateTime.now(),
      'present',
      'firstVerifier',
      ['student.identifier', 'organization.legalName', 'organization.address']);
  print(holder.getExchangeHistoryEntriesForCredential(keyList.first));

  //Verifier looks, if presentation is correct
  print(
      'Presentation correct?: ${await verifyPresentation(presentation, challenge, erc1056: erc1056, revocationRegistry: revocationRegistry)}');

  //Verifier checks, if plaintext Credential belongs to the Credential
  // in the presentation
  Map<String, dynamic> presMapV2 = jsonDecode(presentation);
  var credSubject = presMapV2['verifiableCredential'][0]['credentialSubject'];
  print(
      'Disclosed Plaintext and Credential in Presentation Match?: ${compareW3cCredentialAndPlaintext(credSubject, plaintextDis)}');

  holder.closeBoxes();
}
