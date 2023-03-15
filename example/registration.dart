import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/did.dart';
import 'package:dart_ssi/wallet.dart';
import 'package:uuid/uuid.dart';

void main() async {
  const String rpcUrl = 'http://127.0.0.1:7545';
  var erc1056 = Erc1056(rpcUrl,
      contractAddress: '0x0eE301c92471234038E320153A7F650ab9a72e28');

  //init issuer
  var issuer = WalletStore('exampleData/issuer');
  await issuer.openBoxes('iss1passsword');

  //init Holder
  var holder = WalletStore('exampleData/holder');
  await holder.openBoxes('holderPW');

  // Holder generates its did for this connection
  var did = await holder.getNextConnectionDID();

  //issuer generates did for this connection
  var didIss = await issuer.getNextConnectionDID();

  //They exchange their dids, e.g. during a registration process

  // now both can store them
  var com = holder.getConnection(did)!;
  await holder.storeConnection(didIss, 'Issuer1', com.hdPath);

  var comIss = issuer.getConnection(didIss)!;
  await issuer.storeConnection(did, 'student1', comIss.hdPath);

  // meeting the next time they can authenticate each Other by e.g. signing a challenge.
  // Here it is only shown that the holder authenticate himself with the issuer.
  var challenge = Uuid().v4();

  var jws = await signStringOrJson(
      wallet: holder, didToSignWith: did, toSign: challenge);

  print(await verifyStringSignature(jws, expectedDid: did, erc1056: erc1056));
}
