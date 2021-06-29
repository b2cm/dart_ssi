import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_ssi_wallet/flutter_ssi_wallet.dart';
import 'package:flutter_ssi_wallet/src/ethereum_connector.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:web3dart/credentials.dart';
import 'package:web3dart/crypto.dart';

import 'package:web3dart/web3dart.dart';
import 'package:http/http.dart'; //You can also import the browser version

void main() async {


  const String rpcUrl = 'http://127.0.0.1:7545';
  //String contractAddress = '0xF7551cC988437d0D33A615cCE4716D8384Aa8AEB';
  String contractAddress = '0xA46f0bB111fF7186505AB3091b28412d689aF512';
  var erc1056 = Erc1056(rpcUrl, contractAddress: contractAddress);
  var ganacheAccounts = new WalletStore('ganacheNew');
  await ganacheAccounts.openBoxes('ganache');
  ganacheAccounts.initialize(
      mnemonic:
      'furnace party vehicle liberty vacuum thank march voyage rail fluid wonder sing');

  var ganacheDid5 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/4');
  var ganacheDid6 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/5');
  var ganacheDid7 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/6');
  var ganacheDid8 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/7');
  var ganacheDid9 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/8');
  var ganacheDid10 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/9');

  late DeployedContract _erc1056contract;

  EthereumAddress _didToAddress(String did) {
    var splitted = did.split(':');
    return EthereumAddress.fromHex(splitted.last);
  }

  group('Change Owner Contract', () {
    test('set new extern owner', () async {

      late WalletStore wallet;
      wallet = WalletStore('tests');
      await wallet.openBoxes('password');
      wallet.initialize();

      //Test-Connections
      int _chainId = 1337;
      var httpClient = new Client();
      var ethClient = new Web3Client(rpcUrl, httpClient);
      const String privateKeySpender =
          '80ebf26c2b59f216ba156374fcb2de4bbfd7aae4f5c08b00205ca5e552f532ac';

      //Test-Keys
      String contractAddress = '0xA46f0bB111fF7186505AB3091b28412d689aF512';
      String privateKeyContract = ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/0');
      String privateKeyFrom = ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/4');
      String privateKeyTo = ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/5');

      //Test-Accounts
      String addressFrom = ganacheDid5.substring(9);
      String addressTo = ganacheDid6.substring(9);
      String addressSpender = ganacheDid7.substring(9);

      //get a new did
      var newDid = await wallet.getNextCredentialDID();

      //final credentials = await ethClient.credentialsFromPrivateKey(ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/6'),);
      final credentials = await ethClient.credentialsFromPrivateKey(privateKeyFrom);

      //Create a transaction with both sender and recipient
      Transaction transaction = Transaction(
        from: EthereumAddress.fromHex(addressFrom),
        to: EthereumAddress.fromHex(addressTo),
        //gasPrice: EtherAmount.inWei(BigInt.one),
        //maxGas: 100000,
        nonce: 0x101,
        value: EtherAmount.fromUnitAndValue(EtherUnit.ether, 101),
      );

      //Call with the necessary information, which is still to be adapted
      await erc1056.changeOwnerSigned(
          ethClient,
          newDid,
          credentials,
          transaction,
          addressFrom,
          addressTo,
          addressSpender,
          privateKeyFrom,
          privateKeyTo,
          privateKeySpender,
          _chainId);

    });
  });
}