import 'dart:convert';
import 'dart:io';

import 'package:flutter_ssi_wallet/flutter_ssi_wallet.dart';
import 'package:uuid/uuid.dart';

//This example shows how holder an verifier could interact.
//You should run the example issuance.dart before to make sure, the credential exists.

main() async {
  const String rpcUrl = 'http://127.0.0.1:7545';
  var erc1056 = Erc1056(rpcUrl,
      contractAddress: '0x0eE301c92471234038E320153A7F650ab9a72e28');

  //init Holder Wallet
  var holder = new WalletStore('example/holder');
  await holder.openBoxes('holderPW');

  //Verifier generates nonce/challenge for this presentation
  // and sends it to holder
  var challenge = new Uuid().v4();

  //Holder searches credential in Wallet and builds a Presentation with the W3C-Credential
  var allCredentials = holder.getAllCredentials();
  var keyList = allCredentials.keys;
  Credential c = allCredentials[keyList.first];
  var presentation = buildPresentation([c.w3cCredential], holder, challenge);
  await new File('example/presentation.json').writeAsString(presentation);

  //Holder hides all values he wouldn't show
  Map<String, dynamic> plaintextDis = jsonDecode(c.plaintextCredential);
  plaintextDis['issuanceDate'] as Map<String, dynamic>
    ..remove('value')
    ..remove('salt');
  var student = plaintextDis['student'];
  var keyListStudent = ['givenName', 'familyName', 'birthDate', 'birthPlace'];
  for (String key in keyListStudent) {
    student[key] as Map<String, dynamic>..remove('value')..remove('salt');
  }
  var address = student['address'] as Map<String, dynamic>;
  var keyListAddress = ['addressLocality', 'postalCode', 'streetAddress'];
  for (String key in keyListAddress) {
    address[key] as Map<String, dynamic>..remove('value')..remove('salt');
  }
  student['address'] = address;
  plaintextDis['student'] = student;
  var imma = plaintextDis['immatrikulation'];
  var keyListImma = [
    'courseOfStudies',
    'degreeOfCompletion',
    'group',
    'studyType',
    'collegeSemester',
    'duration',
    'currentSemester',
    'holidaySemester'
  ];
  for (String key in keyListImma) {
    imma[key] as Map<String, dynamic>..remove('value')..remove('salt');
  }
  plaintextDis['immatrikulation'] = imma;
  await new File('example/disclosedImma.json')
      .writeAsString(jsonEncode(plaintextDis));

  //Holder sends both to verifier

  //Verifier looks, if presentation is correct
  print(
      'Presentation correct?: ${await verifyPresentation(presentation, erc1056, challenge, rpcUrl)}');

  //Verifier checks, if plaintext Credential belongs to the Credential
  // in the presentation
  Map<String, dynamic> presMapV2 = jsonDecode(presentation);
  var credSubject = presMapV2['verifiableCredential'][0]['credentialSubject'];
  print(
      'Disclosed Plaintext and Credential in Presentation Match?: ${compareW3cCredentialAndPlaintext(credSubject, plaintextDis)}');

  holder.closeBoxes();
}
