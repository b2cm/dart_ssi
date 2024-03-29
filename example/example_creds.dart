import 'dart:io';

import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/did.dart';
import 'package:dart_ssi/wallet.dart';
import 'package:http/http.dart';
import 'package:uuid/uuid.dart';
import 'package:web3dart/web3dart.dart';

void main() async {
  const String rpcUrl = 'http://127.0.0.1:7545';
  const String spenderPrivateKey =
      '80ebf26c2b59f216ba156374fcb2de4bbfd7aae4f5c08b00205ca5e552f532ac';
  final web3 = Web3Client(rpcUrl, Client());

  var erc1056 = Erc1056(rpcUrl,
      contractAddress: '0x0eE301c92471234038E320153A7F650ab9a72e28');
  var revocationRegistry = RevocationRegistry(rpcUrl);

  //init issuer
  var issuer = WalletStore('exampleData/issuer');
  await issuer.openBoxes('iss1passsword');
  await issuer.initialize(); //comment this line if trying a second time
  await issuer.initializeIssuer(); //comment this line if trying a second time
  //generate Revocation Contract and store its address
  var revocation = RevocationRegistry(rpcUrl);
  // get some Ether
  await web3.sendTransaction(
      EthPrivateKey.fromHex(spenderPrivateKey),
      Transaction(
          to: EthereumAddress.fromHex(
              issuer.getStandardIssuerDid()!.substring(9)),
          value: EtherAmount.fromInt(EtherUnit.ether, 1)));
  var revAddress =
      await revocation.deploy((await issuer.getStandardIssuerPrivateKey())!);
  issuer.storeConfigEntry('revAddress', revAddress);

  //init Holder
  var holder = WalletStore('exampleData/holder');
  await holder.openBoxes('holderPW');
  await holder.initialize(); //comment this line if trying a second time

  //*******************************************
  //** Holder gets a Credential from Issuer **
  //*******************************************

  //Holder generates a new DID for this credential
  var nameDid = await holder.getNextCredentialDID();
  var driversLicenseDid = await holder.getNextCredentialDID();
  var emailDid = await holder.getNextCredentialDID();

  //Holder fill in it's data in a template
  Map<String, dynamic> name = {
    'type': 'NameCredential',
    'issuanceDate': DateTime.now().toIso8601String().substring(0, 10),
    'givenName': 'Max',
    'familyName': 'Mustermann'
  };

  Map<String, dynamic> driversLicense = {
    'type': 'NameCredential',
    'issuanceDate': DateTime.now().toIso8601String().substring(0, 10),
    'allowedVehicleCategories': ['A', 'B']
  };

  Map<String, dynamic> email = {
    'type': 'MailNameCredential',
    'issuanceDate': DateTime.now().toIso8601String().substring(0, 10),
    'givenName': 'Max',
    'familyName': 'Mustermann',
    'email': 'mustermann@example.com'
  };

  //Holder hashes all values an sends this to issuer
  var plaintextName = buildPlaintextCredential(name, nameDid);
  await File('example/plaintextName.json').writeAsString(plaintextName);
  var plaintextDriversLicense =
      buildPlaintextCredential(driversLicense, driversLicenseDid);
  await File('example/plaintextDriversLicense.json')
      .writeAsString(plaintextDriversLicense);
  var plaintextEmail = buildPlaintextCredential(email, emailDid);
  await File('example/plaintextEmail.json').writeAsString(plaintextEmail);

  //Issuer checks the values and builds a W3C Verifiable credential over
  //a hashes of each attribute value
  var w3cName = buildW3cCredentialwithHashes(
      plaintextName, issuer.getStandardIssuerDid(),
      revocationRegistryAddress: revAddress);
  var w3cDiversLicense = buildW3cCredentialwithHashes(
      plaintextDriversLicense, issuer.getStandardIssuerDid(),
      revocationRegistryAddress: revAddress);
  var w3cEmail = buildW3cCredentialwithHashes(
      plaintextEmail, issuer.getStandardIssuerDid(),
      revocationRegistryAddress: revAddress);

  //Issuer signs the credential and sends it to the Holder
  var signedName = await signCredential(issuer, w3cName);
  await File('example/signedName.json').writeAsString(signedName);
  var signedDriversLicense = await signCredential(issuer, w3cDiversLicense);
  await File('example/signedDiversLicense.json')
      .writeAsString(signedDriversLicense);
  var signedEmail = await signCredential(issuer, w3cEmail);
  await File('example/signedEmail.json').writeAsString(signedEmail);

  //Issuer stores it in its own history to be able to revoke it
  issuer.toIssuingHistory(nameDid, plaintextName, signedName);
  issuer.toIssuingHistory(
      driversLicenseDid, plaintextDriversLicense, signedDriversLicense);
  issuer.toIssuingHistory(emailDid, plaintextEmail, w3cEmail);

  //Holder checks signature
  print(
      'Is name-credential credential correct? : ${await verifyCredential(signedName, erc1056: erc1056, revocationRegistry: revocationRegistry)}');
  print(
      'Is drivers-license-credential credential correct? : ${await verifyCredential(signedDriversLicense, erc1056: erc1056, revocationRegistry: revocationRegistry)}');
  print(
      'Is email-credential credential correct? : ${await verifyCredential(signedEmail, erc1056: erc1056, revocationRegistry: revocationRegistry)}');
  //Holder stores Credential in wallet
  await holder.storeCredential(
      signedName, plaintextName, holder.getCredential(nameDid)!.hdPath);
  await holder.storeCredential(signedDriversLicense, plaintextDriversLicense,
      holder.getCredential(driversLicenseDid)!.hdPath);
  await holder.storeCredential(
      signedEmail, plaintextEmail, holder.getCredential(emailDid)!.hdPath);

  // generates challenge for presentations
  var challenge1 = Uuid().v4();
  print('name-challenge: $challenge1');
  var challenge2 = Uuid().v4();
  print('name-challenge: $challenge2');
  var challenge3 = Uuid().v4();
  print('email-challenge: $challenge3');

  //disclose values in credentials
  var disclosedName = discloseValues(plaintextName, ['familyName']);
  await File('example/DisclosedName.json').writeAsString(disclosedName);

  var disclosedDL = discloseValues(
      plaintextDriversLicense, ['allowedVehicleCategories.0', 'issuanceDate']);
  await File('example/DisclosedDL.json').writeAsString(disclosedDL);

  var disclosedEmail =
      discloseValues(plaintextEmail, ['givenName', 'familyName']);
  await File('example/DisclosedEmail.json').writeAsString(disclosedEmail);

  //build Presentation with one credential without disclosed credential
  var presentationOne =
      await buildPresentation([signedName], holder, challenge1);
  await File('example/PresentationOne.json').writeAsString(presentationOne);

  //build Presentation with both credentials without disclosed ones
  var presentationTwo = await buildPresentation(
      [signedName, signedDriversLicense], holder, challenge2);
  await File('example/PresentationTwo.json').writeAsString(presentationTwo);

  //build presentation with disclosed credentials
  var presentationThree = await buildPresentation(
      [signedEmail], holder, challenge3,
      disclosedCredentials: [disclosedEmail]);
  await File('example/PresentationThree.json').writeAsString(presentationThree);

  print(
      'Is Presentation one correct?: ${await verifyPresentation(presentationOne, challenge1, erc1056: erc1056, revocationRegistry: revocationRegistry)}');
  print(
      'Is Presentation two correct?: ${await verifyPresentation(presentationTwo, challenge2, erc1056: erc1056, revocationRegistry: revocationRegistry)}');
  //here the comparison with the containing disclosed credentials is done while checking presentation
  print(
      'Is Presentation three correct?: ${await verifyPresentation(presentationThree, challenge3, erc1056: erc1056, revocationRegistry: revocationRegistry)}');

  print(
      'Do W3C-Credential and Plaintext match?: ${compareW3cCredentialAndPlaintext(signedName, disclosedName)}');

  await issuer.closeBoxes();
  await holder.closeBoxes();
}
