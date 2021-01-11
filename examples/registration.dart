import 'package:flutter_ssi_wallet/flutter_ssi_wallet.dart';
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
              issuer.getStandardIssuerDid().substring(9)),
          value: EtherAmount.fromUnitAndValue(EtherUnit.ether, 1)));
  var revAddress =
      await revocation.deploy(issuer.getStandardIssuerPrivateKey());
  issuer.storeConfigEntry('revAddress', revAddress);

  //init Holder
  var holder = new WalletStore('example/holder');
  await holder.openBoxes('holderPW');
  holder.initialize(); //comment this line if trying a second time

  // Holder generates its did for this connection
  var did = await holder.getNextCommunicationDID();

  //issuer generates did for this connection
  var didIss = await issuer.getNextCommunicationDID();

  //They exchange their dids, e.g. during a registration process

  // now both can store them
  var com = holder.getCommunication(did);
  holder.storeCommunication(didIss, 'Issuer1', com.hdPath);

  var comIss = issuer.getCommunication(didIss);
  issuer.storeCommunication(did, 'student1', comIss.hdPath);

  // meeting the next time they can authenticate each Other by e.g. signing a challenge.
  // Here it is only shown that the holder authenticate himself with the issuer.
  var challenge = Uuid().v4();

  var jws = signString(holder, did, challenge);

  print(await verifyStringSignature(challenge, jws, did, erc1056));
}
