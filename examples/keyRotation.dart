import 'package:dart_ssi/did.dart';
import 'package:dart_ssi/wallet.dart';
import 'package:http/http.dart';
import 'package:web3dart/web3dart.dart';

void main() async {
  const String rpcUrl = 'http://127.0.0.1:7545';
  const String spenderPrivateKey =
      '80ebf26c2b59f216ba156374fcb2de4bbfd7aae4f5c08b00205ca5e552f532ac';
  final web3 = Web3Client(rpcUrl, Client());
  var erc1056 = Erc1056(rpcUrl,
      contractAddress: '0x0eE301c92471234038E320153A7F650ab9a72e28');

  var holder = WalletStore('example/holder');
  await holder.openBoxes('holderPW');

  //get the did the keys should be rotated for
  var did = holder.getAllCredentials().keys.first;

  //get some ether
  await web3.sendTransaction(
      EthPrivateKey.fromHex(spenderPrivateKey),
      Transaction(
          to: EthereumAddress.fromHex(did.substring(9)),
          value: EtherAmount.fromUnitAndValue(EtherUnit.ether, 1)));

  //get a new did
  var newDid = await holder.getNextCredentialDID();

  //rotate it
  await erc1056.changeOwner(
      (await holder.getPrivateKeyForCredentialDid(did))!, did, newDid);

  //store
  var cred = holder.getCredential(did)!;
  await holder.storeCredential(cred.w3cCredential, cred.plaintextCredential,
      holder.getCredential(newDid)!.hdPath,
      credDid: did);

  holder.closeBoxes();
}
