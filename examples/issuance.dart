import 'dart:io';

import 'package:dart_web3/dart_web3.dart';
import 'package:flutter_ssi_wallet/flutter_ssi_wallet.dart';
import 'package:http/http.dart';

void main() async {
  const String rpcUrl = 'http://127.0.0.1:7545';
  const String spenderPrivateKey =
      '80ebf26c2b59f216ba156374fcb2de4bbfd7aae4f5c08b00205ca5e552f532ac';
  final web3 = Web3Client(rpcUrl, Client());

  var erc1056 = Erc1056(rpcUrl,
      contractAddress: '0x0eE301c92471234038E320153A7F650ab9a72e28');
  var revocationRegistry = RevocationRegistry(rpcUrl);

  //init issuer
  var issuer = new WalletStore('example/issuer');
  await issuer.openBoxes('iss1passsword');
  issuer.initialize(); //comment this line if trying a second time
  await issuer.initializeIssuer(); //comment this line if trying a second time
  //generate Revocation Contract and store its address
  var revocation = RevocationRegistry(rpcUrl);
  // get some Ether
  await web3.sendTransaction(
      EthPrivateKey.fromHex(spenderPrivateKey),
      Transaction(
          to: EthereumAddress.fromHex(
              issuer.getStandardIssuerDid()!.substring(9)),
          value: EtherAmount.fromUnitAndValue(EtherUnit.ether, 1)));
  var revAddress =
      await revocation.deploy(issuer.getStandardIssuerPrivateKey()!);
  issuer.storeConfigEntry('revAddress', revAddress);

  //init Holder
  var holder = new WalletStore('example/holder');
  await holder.openBoxes('holderPW');
  holder.initialize(); //comment this line if trying a second time

  //*******************************************
  //** Holder gets a Credential from Issuer **
  //*******************************************

  //Holder generates a new DID for this credential
  var immaDid = await holder.getNextCredentialDID();

  //Holder fill in it's data in a template
  Map<String, dynamic> immatrikulation = {
    '@context': ['https://bccm-ssi.hs-mittweida.de/credentials'],
    'type': 'ImmatrikulationCredential',
    'issuanceDate': DateTime.now().toIso8601String().substring(0, 10),
    'student': {
      'type': 'Student',
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
      'identifier': '12345'
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
    'immatrikulation': {
      'type': 'Immatrikulation',
      'courseOfStudies': 'Angewandte Informatik - IT-Sicherheit',
      'degreeOfCompletion': 'B.Sc.',
      'group': 'IF17wI-B',
      'studyType': 'Vollzeitstudium',
      'collegeSemester': 7,
      'duration': 6,
      'currentSemester': 7,
      'holidaySemester': 0
    }
  };

  //Holder hashes all values an sends this to issuer
  var plaintextCred = buildPlaintextCredential(immatrikulation, immaDid);
  await new File('example/immaPlaintext.json').writeAsString(plaintextCred);

  //Issuer checks the values and builds a W3C Verifiable credential over
  //a hashes of each attribute value
  var w3cImma = buildW3cCredentialwithHashes(
      plaintextCred, issuer.getStandardIssuerDid(),
      revocationRegistryAddress: revAddress);

  //Issuer signs the credential and sends it to the Holder
  var signedImma = signCredential(issuer, w3cImma);
  await new File('example/signedImma.json').writeAsString(signedImma);
  //Issuer stores it in its own history to be able to revoke it
  issuer.toIssuingHistory(immaDid, plaintextCred, signedImma);

  //Holder checks signature
  print(
      'Is my credential correct? : ${await verifyCredential(signedImma, erc1056: erc1056, revocationRegistry: revocationRegistry)}');
  //Holder stores Credential in wallet
  await holder.storeCredential(
      signedImma, plaintextCred, holder.getCredential(immaDid)!.hdPath);

  await issuer.closeBoxes();
  await holder.closeBoxes();
}
