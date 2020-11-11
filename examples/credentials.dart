import 'dart:convert';
import 'dart:io';

import 'package:flutter_ssi_wallet/flutter_ssi_wallet.dart';
import 'package:flutter_ssi_wallet/src/hive_model.dart';
import 'package:hive/hive.dart';

void main() async {
  Hive.registerAdapter(CredentialAdapter());

  //init issuer
  var issuer = new WalletStore('issuer1');
  await issuer.openBoxes('iss1passsowrd');
  issuer.initialize(); //comment this line if trying a second time
  await issuer.initializeIssuer(); //comment this line if trying a second time

  //init Holder
  var holder = new WalletStore('holder');
  await holder.openBoxes('holderPW');
  holder.initialize(); //comment this line if trying a second time

  // init Verifier
  var verifier = new WalletStore('verifier');
  await verifier.openBoxes('verifierPassword');
  verifier.initialize(); //comment this line if trying a second time

  //*******************************************
  //** Holder gets a Credential from Issuer **
  //*******************************************

  //Holder generates a new DID for this credential
  var immaDid = await holder.getNextDID();

  //Holder fill in it's data in a template
  Map<String, dynamic> immatrikulation = {
    'dateCreated': DateTime.now().toIso8601String().substring(0, 10),
    'title': '???',
    'student': {
      'givenName': 'Max',
      'familyName': 'Mustermann',
      'birthDate': new DateTime(1999, 10, 14).toIso8601String(),
      'birthPlace': 'Berlin',
      'address': {
        'addressLocality': 'Mittweida',
        'postalCode': '09648',
        'streetAddress': 'Am Schwanenteich 8'
      },
      'identifier': '123456'
    },
    'organization': {
      'legalName': 'Hochschule Mittweida University of Applied Sciences',
      'address': {
        'adressLocality': 'Mittweida',
        'postalCode': '09648',
        'streetAdress': 'Technikumplatz 17'
      }
    },
    'immatrikulation': {
      'courseOfStudies': 'Cybercrime/Cybersecurity',
      'title': 'M.Sc.',
      'group': 'CY20wC-M',
      'type': 'Vollzeitstudium',
      'duration': '4 Semester',
      'currentSemester': 1,
      'holidaySemester': 0
    }
  };
  //Holder hashes all values an sends this to issuer
  var plaintextCred = buildHashedValueCredential(immatrikulation);
  await new File('immaPlaintext.json').writeAsString(plaintextCred);
  //Issuer checks the values and builds a W3C Verifiable credential over
  //a hash of all value-hashes
  var w3CImmaCred = buildW3cCredentialToPlaintextCred(
      plaintextCred, immaDid, issuer.getStandardIssuerDid());
  //Issuer signs the credential
  var signedImma = signCredential(issuer, w3CImmaCred);
  await new File('signedImma.json').writeAsString(signedImma);

  //Holder checks signature
  print(verifyCredential(signedImma));
  //Holder stores Credential in wallet
  await holder.storeCredential(
      signedImma, plaintextCred, holder.getCredential(immaDid).hdPath);

  //*****************************************************
  //** Holder shows this Credential to verifier and    **
  //** only discloses the University, where he studies **
  //*****************************************************
  //Holder builds a Presentation with the W3C-Credential
  Credential c = holder.getCredential(immaDid);
  var presentation = buildPresentation([c.w3cCredential], holder);
  await new File('presentation.json').writeAsString(presentation);
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
  var immaHash = buildCredentialHash(imma);
  plaintextDis['immatrikulation'] = {'hash': immaHash};

  await new File('disclosedImma.json').writeAsString(jsonEncode(plaintextDis));
  //Holder sends both to verifier
  //Verifier looks, if presentation is correct
  print(verifyPresentation(presentation));
  //Verifier checks, if plaintext Credential belogs to the Credential in the presentation
  var disclosedHash = buildCredentialHash(plaintextDis);
  var presMap = jsonDecode(presentation);
  var hashInPresentation =
      presMap['verifiableCredential'][0]['credentialSubject']['claimHash'];
  print(
      'Hash from given Plaintext: $disclosedHash; Hash found in Presentation: $hashInPresentation; equivalent: ${disclosedHash == hashInPresentation}');
}
