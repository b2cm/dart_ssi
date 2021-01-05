import 'package:flutter_ssi_wallet/flutter_ssi_wallet.dart';

//This example shows how an issuer could revoke an issued credential
//You should run the example issuance.dart before to make sure, the credential exists.

void main() async {
  const String rpcUrl = 'http://127.0.0.1:7545';

  var issuer = WalletStore('example/issuer');
  await issuer.openBoxes('iss1passsword');

  //get address of own revocation contract
  var revAddress = issuer.getConfigEntry('revAddress');
  print('Address of Revocation contract: $revAddress');
  var revocationContract =
      RevocationRegistry(rpcUrl, contractAddress: revAddress);

  //get did of credential that should be revoked from history
  var issHistory = issuer.getAllIssuedCredentials();
  var did = issHistory.keys.first;

  // to show, that it is not revoked now
  print('Is credential revoked? : ${await revocationContract.isRevoked(did)}');

  //revoke it
  await revocationContract.revoke(issuer.getStandardIssuerPrivateKey(), did);

  //show, that it is revoked
  print('Is credential revoked? : ${await revocationContract.isRevoked(did)}');

  issuer.closeBoxes();
}
