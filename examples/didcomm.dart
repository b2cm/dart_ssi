/*
This Example demonstrates the usage of this library with the following story:
Alice would buy a discounted Annual ticket for the Art museum. She gets the
discount because she is a student at an university. So she has to present
her student card to the museum.
After this the museum issues the Annual Ticket to Alice.

On a high level the process looks like this:

  Alice                                       Museum
     <--request presentation (student-card)-------
     ---presentation (student card)-------------->
     <--propose-credential (annual ticket)--------
     ---request-credential (annual ticket)------->
     <--issue-credential (annual ticket)----------
 */

import 'dart:convert';

import 'package:dart_web3/crypto.dart';
import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/did.dart';
import 'package:dart_ssi/didcomm.dart';
import 'package:dart_ssi/util.dart';
import 'package:dart_ssi/wallet.dart';
import 'package:json_path/json_path.dart';
import 'package:json_schema2/json_schema2.dart';
import 'package:uuid/uuid.dart';

void main() async {
  var alice = WalletStore('example/didcomm/alice');
  await alice.openBoxes('alicePassword');
  await alice.initialize();
  await _issueStudentCard(alice);

  var museum = WalletStore('example/didcomm/museum');
  await museum.openBoxes('museumPassword');
  await museum.initialize();
  await museum.initializeIssuer(KeyType.ed25519);
  await _issueBusinessId(museum);

  // ****** Museum ********
  var museumDid = await museum.getNextConnectionDID(KeyType.x25519);
  var presentationDefinition =
      PresentationDefinition(id: Uuid().v4(), inputDescriptors: [
    InputDescriptor(
        id: Uuid().v4(),
        name: 'Studentcard-Descriptor',
        constraints: InputDescriptorConstraints(fields: [
          InputDescriptorField(
              path: [JsonPath(r'$.type')],
              filter: JsonSchema.createSchema({
                'type': 'array',
                'contains': {'type': 'string', 'pattern': 'StudentCard'}
              }))
        ])),
  ]);
  var requestPresentationStudentCard =
      RequestPresentation(presentationDefinition: [
    PresentationDefinitionWithOptions(
        domain: 'https://museum-of-modern-art.com',
        challenge: Uuid().v4(),
        presentationDefinition: presentationDefinition)
  ]);
  var oob = OutOfBandMessage(from: museumDid, attachments: [
    Attachment(
        data: AttachmentData(json: requestPresentationStudentCard.toJson()))
  ]);
  var oobUrl = oob.toUrl('http', 'museum-of-modern-art.com', 'somePath');
  print(oob.attachments![0].data.json);
  //This Message is rendered as QR-Code

  // ***** ALICE *****

  //Alice scans the QR-Code and decodes the message
  var decodedOOB = oobMessageFromUrl(oobUrl);
  //Alice resolves the Did-Document of the sender
  var ddoMuseum = await resolveDidDocument(decodedOOB.from!);
  //Alice converts the Did-Document in a form that is easier to use
  ddoMuseum = ddoMuseum.resolveKeyIds();
  ddoMuseum = ddoMuseum.convertAllKeysToJwk();
  // Alice checks the Attachment and notice, that it is request-Presentation Message
  RequestPresentation request;
  try {
    print(decodedOOB.attachments![0].data.json);
    request =
        RequestPresentation.fromJson(decodedOOB.attachments![0].data.json);
  } catch (e) {
    print('This is no RequestPresentation Message');
    throw Exception(e);
  }

  //Alice searches her Wallet for matching credentials
  var allCreds = alice.getAllCredentials();
  List<Map<String, dynamic>> allW3CCreds = [];
  for (var cred in allCreds.values) {
    if (cred.w3cCredential != '')
      allW3CCreds.add(jsonDecode(cred.w3cCredential));
  }
  var searchResult = searchCredentialsForPresentationDefinition(
      allW3CCreds, request.presentationDefinition[0].presentationDefinition);

  //Alice realize, that she should show her Student card and build verifiable Presentation out of it
  var presentation = await buildPresentation(
      [searchResult[0]], alice, request.presentationDefinition[0].challenge);
  //Now she puts this in a Presentation Message
  var presentationMessage = Presentation(
      verifiablePresentation: [VerifiablePresentation.fromJson(presentation)]);
  //alice generates a did she encrypts the message with
  var connectionDidAlice = await alice.getNextConnectionDID(KeyType.x25519);
  var privateKey =
      await alice.getPrivateKeyForConnectionDid(connectionDidAlice);
  var encryptedMessage = DidcommEncryptedMessage.fromPlaintext(
      keyWrapAlgorithm: KeyWrapAlgorithm.ecdhES,
      senderPrivateKeyJwk: {
        'kty': 'OKP',
        'crv': 'X25519',
        'kid': '$connectionDidAlice#${connectionDidAlice.split(':')[2]}',
        'd': removePaddingFromBase64(
            base64UrlEncode(hexToBytes(privateKey!).sublist(0, 32)))
      },
      recipientPublicKeyJwk: [ddoMuseum.keyAgreement![0].publicKeyJwk],
      plaintext: presentationMessage);
  //This message she could send to the museum

  //***** Museum *******

  //The museum receives the Message. Because its anoncrypted, the museum could encrypt it without looking up a did-Document
  var museumPrivateKey = await museum.getPrivateKeyForConnectionDid(museumDid);
  var decrypted = encryptedMessage.decrypt({
    'kty': 'OKP',
    'crv': 'X25519',
    'kid': '$museumDid#${museumDid.split(':')[2]}',
    'd': removePaddingFromBase64(
        base64UrlEncode(hexToBytes(museumPrivateKey!).sublist(0, 32)))
  });

  //To send message back, the museum looks for the sender in protected Header skid value
  Map<String, dynamic> decodedHeader = jsonDecode(utf8.decode(
      base64Decode(addPaddingToBase64(encryptedMessage.protectedHeader))));
  var senderKid = decodedHeader['skid'];
  var sender = senderKid.split('#')[0];
  print(sender);
  var senderDDO = await resolveDidDocument(sender);
  senderDDO = senderDDO.convertAllKeysToJwk();
  senderDDO = senderDDO.resolveKeyIds();

  //Normally a Wallet has to check which Type it gets here. For this example we know, that it is a plaintext-Massage
  decrypted = decrypted as DidcommPlaintextMessage;
  if (decrypted.type != 'https://didcomm.org/present-proof/3.0/presentation')
    throw Exception('Presentation Message expected');
  var presentationMessageReceived = Presentation.fromJson(decrypted.toJson());

  //verifyPresentation
  var verified = await verifyPresentation(
      presentationMessageReceived.verifiablePresentation[0].toJson(),
      requestPresentationStudentCard.presentationDefinition[0].challenge);
  if (!verified) throw Exception('Presentation could not been verified');

  //check if the credential inside matches the presentation Definition
  var result = searchCredentialsForPresentationDefinition([
    presentationMessageReceived
        .verifiablePresentation[0].verifiableCredential[0]
        .toJson()
  ], presentationDefinition);
  if (result.length != 1) throw Exception('Credential dont match definition');

  //Now the Museum could start the issuance process for the annual ticket
  var museumIssuerDid = await museum.getStandardIssuerDid(KeyType.ed25519);
  var credentialSubject = {
    'id': 'did:key:00000',
    'institution': 'Museum of modern Art',
    'ticketType': 'Discounted Annual Ticket'
  };
  var offer = OfferCredential(detail: [
    LdProofVcDetail(
        credential: VerifiableCredential(
            context: [
              'https://www.w3.org/2018/credentials/v1',
              'https://www.example.com/annualTicket/v1'
            ],
            type: [
              'VerifiableCredential',
              'AnnualTicket'
            ],
            credentialSubject: credentialSubject,
            issuanceDate: DateTime.now(),
            issuer: museumIssuerDid),
        options: LdProofVcDetailOptions(proofType: 'Ed25519Signature2020'))
  ]);

  var encryptedOffer =
      DidcommEncryptedMessage.fromPlaintext(senderPrivateKeyJwk: {
    'kty': 'OKP',
    'crv': 'X25519',
    'kid': '$museumDid#${museumDid.split(':')[2]}',
    'd': removePaddingFromBase64(
        base64UrlEncode(hexToBytes(museumPrivateKey).sublist(0, 32)))
  }, recipientPublicKeyJwk: [
    senderDDO.keyAgreement![0].publicKeyJwk
  ], plaintext: offer);

  //This authcrypted Message is sent to alice

  //**** Alice *******
  //Alice decrypts the message (she know, that it is from the museum)
  var decryptedOffer = encryptedOffer.decrypt({
    'kty': 'OKP',
    'crv': 'X25519',
    'kid': '$connectionDidAlice#${connectionDidAlice.split(':')[2]}',
    'd': removePaddingFromBase64(
        base64UrlEncode(hexToBytes(privateKey).sublist(0, 32)))
  }, ddoMuseum.keyAgreement![0].publicKeyJwk);

  //Here aswell we know that it is plaintext Message and has a type of offer-credential
  var receivedOffer = OfferCredential.fromJson(decryptedOffer.toJson());
  //Alice checks, if the did the credential should issued to is controlled by her
  var did = receivedOffer.detail![0].credential.credentialSubject['id'];
  print(did);
  var key;
  try {
    key = await alice.getPrivateKeyForCredentialDid(did);
  } catch (e) {
    print(e);
  }
  if (key == null) {
    print('I do not control this did');
  }
  // in this case alice must sent a propose credential with a correct did
  var vc = receivedOffer.detail![0].credential;
  var aliceCredDid = await alice.getNextCredentialDID(KeyType.ed25519);
  vc.credentialSubject['id'] = aliceCredDid;
  var propose = ProposeCredential(detail: [
    LdProofVcDetail(credential: vc, options: receivedOffer.detail![0].options)
  ]);
  var encryptedPropose =
      DidcommEncryptedMessage.fromPlaintext(senderPrivateKeyJwk: {
    'kty': 'OKP',
    'crv': 'X25519',
    'kid': '$connectionDidAlice#${connectionDidAlice.split(':')[2]}',
    'd': removePaddingFromBase64(
        base64UrlEncode(hexToBytes(privateKey).sublist(0, 32)))
  }, recipientPublicKeyJwk: [
    ddoMuseum.keyAgreement![0].publicKeyJwk
  ], plaintext: propose);
  //This message could be sent to the museum

  //***** Museum ****
  //decrypt message and see, that it is an credential propose that do not differ much from the previous offer
  // (not all chekcing steps are shown here because they are straigth forward)
  var decryptedPropose = encryptedPropose.decrypt({
    'kty': 'OKP',
    'crv': 'X25519',
    'kid': '$museumDid#${museumDid.split(':')[2]}',
    'd': removePaddingFromBase64(
        base64UrlEncode(hexToBytes(museumPrivateKey).sublist(0, 32)))
  }, senderDDO.keyAgreement![0].publicKeyJwk);
  var receivedPropose = ProposeCredential.fromJson(decryptedPropose.toJson());

  //Therefore the museum construct a offer out of it
  var offer2 = OfferCredential(detail: receivedPropose.detail!);
  //This offer is encrypted like all messages before (not shown to avoid too much duplicated code) and sent to alice

  //**** Alice ****

  //Alice receives the offer and notice, that everything is fine now. So she can construct and send a Request-credential Message
  var requestCredential = RequestCredential(detail: [
    LdProofVcDetail(
        credential: offer2.detail![0].credential,
        options: LdProofVcDetailOptions(
            proofType: 'Ed25519Signature2020', challenge: Uuid().v4()))
  ]);

  //This is encrypted and sent

  //**** Museum ****
  //Takes credential from Request, checks if everything is fine and signs it
  var signed = await signCredential(
      museum, requestCredential.detail![0].credential.toJson(),
      challenge: requestCredential.detail![0].options.challenge);
  print(signed);
  //construct a issue credential message and sent credential to alice
  var issueMessage =
      IssueCredential(credentials: [VerifiableCredential.fromJson(signed)]);

  //***** Alice *****
  var receivedVC = issueMessage.credentials![0];
  //verify received credential
  print(await verifyCredential(receivedVC,
      expectedChallenge: requestCredential.detail![0].options.challenge));

  //store credential
  var path = alice.getCredential(aliceCredDid)!.hdPath;
  await alice.storeCredential(receivedVC.toString(), '', path,
      keyType: KeyType.ed25519);

  //check if two creds are there
  var aliceAllCreds = alice.getAllCredentials();
  print(aliceAllCreds.length);
  print(aliceAllCreds);
}

Future<void> _issueStudentCard(WalletStore wallet) async {
  var someUniversity = WalletStore('example/didcomm/someUniversity');
  await someUniversity.openBoxes('password');
  await someUniversity.initialize();
  await someUniversity.initializeIssuer(KeyType.ed25519);
  var issuerDid = someUniversity.getStandardIssuerDid(KeyType.ed25519);
  var holderDid = await wallet.getNextCredentialDID(KeyType.ed25519);

  var studentCard = {
    'id': holderDid,
    'familyName': 'Schmidt',
    'givenName': 'Alice',
    'matriculationNumber': ' 5426745'
  };

  var cred = VerifiableCredential(
      context: [
        'https://www.w3.org/2018/credentials/v1',
        'https://www.example.com/studentCard/v1'
      ],
      type: [
        'VerifiableCredential',
        'StudentCard'
      ],
      issuer: issuerDid,
      credentialSubject: studentCard,
      issuanceDate: DateTime.now());

  var signedCred = await signCredential(someUniversity, cred);
  var hdPath = wallet.getCredential(holderDid)!.hdPath;
  await wallet.storeCredential(signedCred, '', hdPath,
      keyType: KeyType.ed25519);
}

Future<void> _issueBusinessId(WalletStore wallet) async {
  var someIssuer = WalletStore('example/didcomm/someIssuer');
  await someIssuer.openBoxes('password');
  await someIssuer.initialize();
  await someIssuer.initializeIssuer(KeyType.ed25519);
  var issuerDid = someIssuer.getStandardIssuerDid(KeyType.ed25519);
  var holderDid = await wallet.getNextCredentialDID(KeyType.ed25519);

  var businessId = {
    'id': holderDid,
    'name': 'Museum of modern Art',
    'address': {
      'streetAddress': 'Main Street 23',
      'postalCode': '63587',
      'addressLocality': 'Some City'
    }
  };

  var cred = VerifiableCredential(
      context: [
        'https://www.w3.org/2018/credentials/v1',
        'https://www.example.com/businesId/v1'
      ],
      type: [
        'VerifiableCredential',
        'BusinessID'
      ],
      issuer: issuerDid,
      credentialSubject: businessId,
      issuanceDate: DateTime.now());

  var signedCred = await signCredential(someIssuer, cred);
  var hdPath = wallet.getCredential(holderDid)!.hdPath;
  await wallet.storeCredential(signedCred, '', hdPath,
      keyType: KeyType.ed25519);
}
