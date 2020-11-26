import 'dart:convert';
import 'dart:io';

import 'package:flutter_ssi_wallet/flutter_ssi_wallet.dart';
import 'package:flutter_ssi_wallet/src/hive_model.dart';
import 'package:uuid/uuid.dart';

void main() async {
  //init issuer
  var issuer = new WalletStore('issuer1');
  await issuer.openBoxes('iss1passsowrd');
  //issuer.initialize(); //comment this line if trying a second time
  //await issuer.initializeIssuer(); //comment this line if trying a second time

  //init Holder
  var holder = new WalletStore('holder');
  await holder.openBoxes('holderPW');
  //holder.initialize(); //comment this line if trying a second time

  // init Verifier
  var verifier = new WalletStore('verifier');
  await verifier.openBoxes('verifierPassword');
  //verifier.initialize(); //comment this line if trying a second time

  //*******************************************
  //** Holder gets a Credential from Issuer **
  //*******************************************

  //Holder generates a new DID for this credential
  var immaDid = await holder.getNextDID();
  var immaDidV2 = await holder.getNextDID();

  //Holder fill in it's data in a template
  Map<String, dynamic> immatrikulation = {
    '@context': ['https://schema.org'],
    'type': 'ImmatrikulationCredential',
    'dateCreated': DateTime.now().toIso8601String().substring(0, 10),
    'title': '???',
    'student': {
      'type': 'Person',
      'givenName': 'Max',
      'familyName': 'Mustermann',
      'birthDate':
          new DateTime(1999, 10, 14).toIso8601String().substring(0, 10),
      'birthPlace': 'Berlin',
      'address': {
        'type': 'PostalAddress',
        'addressLocality': 'Mittweida',
        'postalCode': '09648',
        'streetAddress': 'Am Schwanenteich 8'
      },
      'identifier': '123456'
    },
    'organization': {
      'type': 'Organization',
      'legalName': 'Hochschule Mittweida University of Applied Sciences',
      'address': {
        'type': 'PostalAddress',
        'addressLocality': 'Mittweida',
        'postalCode': '09648',
        'streetAddress': 'Technikumplatz 17'
      }
    },
    'immatrikulation': [
      {
        'type': 'Immatrikulation',
        'courseOfStudies': 'Angewandte Informatik - IT-Sicherheit',
        'title': 'B.Sc.',
        'group': 'IF17wI-B',
        'studyType': 'Vollzeitstudium',
        'duration': '6 Semester',
        'currentSemester': 7,
        'holidaySemester': 0
      },
      {
        'type': 'Immatrikulation',
        'courseOfStudies': 'Cybercrime/Cybersecurity',
        'title': 'M.Sc.',
        'group': 'CY20wC-M',
        'studyType': 'Vollzeitstudium',
        'duration': '4 Semester',
        'currentSemester': 1,
        'holidaySemester': 0
      }
    ]
  };
  //Holder hashes all values an sends this to issuer
  var plaintextCred = buildPlaintextCredential(immatrikulation);
  await new File('immaPlaintext.json').writeAsString(plaintextCred);
  //Issuer checks the values and builds a W3C Verifiable credential over
  //a hash of all value-hashes
  var w3CImmaCred = buildW3cCredentialSingleHash(
      plaintextCred, immaDid, issuer.getStandardIssuerDid(),
      type: ['HashCredential'],
      context: 'https://identity.hs-mittweida.de/credentials/ld-context/');
  //or
  var w3cImmaV2 = buildW3cCredentialwithHashes(
      plaintextCred, immaDidV2, issuer.getStandardIssuerDid(),
      type: ['ImmatrikulationCredential'],
      context: 'https://identity.hs-mittweida.de/credentials/ld-context/');
  //Issuer signs the credential
  var signedImma = signCredential(issuer, w3CImmaCred);
  await new File('signedImma.json').writeAsString(signedImma);
  var signedImmaV2 = signCredential(issuer, w3cImmaV2);
  await new File('signedImmaV2.json').writeAsString(signedImmaV2);

  //Holder checks signature
  print(verifyCredential(signedImma));
  print(verifyCredential(signedImmaV2));
  //Holder stores Credential in wallet
  await holder.storeCredential(
      signedImma, plaintextCred, holder.getCredential(immaDid).hdPath);
  await holder.storeCredential(
      signedImmaV2, plaintextCred, holder.getCredential(immaDidV2).hdPath);

  //*****************************************************
  //** Holder shows this Credential to verifier and    **
  //** only discloses the University, where he studies **
  //*****************************************************

  //Verifier generates nonce/challenge for this presentation
  // and sends it to holder
  var challenge = new Uuid().v4();

  //Holder builds a Presentation with the W3C-Credential
  Credential c = holder.getCredential(immaDid);
  var presentation = buildPresentation([c.w3cCredential], holder, challenge);
  await new File('presentation.json').writeAsString(presentation);
  // or
  Credential c2 = holder.getCredential((immaDidV2));
  var presentationV2 = buildPresentation([c2.w3cCredential], holder, challenge);
  await new File('presentationV2.json').writeAsString(presentation);
  //Holder hides all values he wouldn't show
  Map<String, dynamic> plaintextDis = jsonDecode(c.plaintextCredential);
  plaintextDis['dateCreated'] as Map<String, dynamic>
    ..remove('value')
    ..remove('salt');
  plaintextDis['title'] as Map<String, dynamic>
    ..remove('value')
    ..remove('salt');
  var student = plaintextDis['student'];
  var studentHash = buildCredentialHash(student);
  plaintextDis['student'] = {'hash': studentHash};
  var imma = plaintextDis['immatrikulation'];
  var immaHash0 = buildCredentialHash(imma[0]);
  var immaHash1 = buildCredentialHash(imma[1]);
  plaintextDis['immatrikulation'] = [
    {'hash': immaHash0},
    {'hash': immaHash1}
  ];

  await new File('disclosedImma.json').writeAsString(jsonEncode(plaintextDis));
  //or
  Map<String, dynamic> disImmaV2 = jsonDecode(c2.plaintextCredential);
  disImmaV2.remove('student');
  disImmaV2.remove('immatrikulation');
  await new File('disclosedImmaV2.json').writeAsString(jsonEncode(disImmaV2));
  //Holder sends both to verifier
  //Verifier looks, if presentation is correct
  print(verifyPresentation(presentation, challenge));
  print(verifyPresentation(presentationV2, challenge));
  //Verifier checks, if plaintext Credential belongs to the Credential
  // in the presentation
  var disclosedHash = buildCredentialHash(plaintextDis);
  var presMap = jsonDecode(presentation);
  var hashInPresentation =
      presMap['verifiableCredential'][0]['credentialSubject']['claimHash'];
  print(
      'Hash from given Plaintext: $disclosedHash; Hash found in Presentation: '
      '$hashInPresentation; equivalent: ${disclosedHash == hashInPresentation}');

  //or
  Map<String, dynamic> presMapV2 = jsonDecode(presentationV2);
  var credSubject = presMapV2['verifiableCredential'][0]['credentialSubject'];
  print(compareW3cCredentialAndPlaintext(credSubject, disImmaV2));

  await issuer.closeBoxes();
  await holder.closeBoxes();
  await verifier.closeBoxes();
}
