import 'dart:convert';

import 'package:dart_web3/dart_web3.dart';
import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/did.dart';
import 'package:http/http.dart' as http;

void main() async {
  const String rpcRopsten =
      'https://ropsten.infura.io/v3/c79506ae5f37452681b58978ac57e927';

  var revRopsten = RevocationRegistry(rpcRopsten,
      contractAddress: '0x77b8cb68d784a46d1bc4b9c9e8894f8fb39d099f');
  var gasRopstenDeploy = await revRopsten
      .estimateGasDeploy('0x0c90C980568f65547E3F3523Da603f4621E90598');
  var gasRopstenRevoke = await revRopsten.estimateRevoke(
      '0x0c90C980568f65547E3F3523Da603f4621E90598',
      'did:ethr:0x4B21e8555816645070e6997E4012C2fa3e81E418');
  var gasRopstenChange = await revRopsten.estimateChangeOwner(
      '0x0c90C980568f65547E3F3523Da603f4621E90598',
      'did:ethr:0xB8E6790943F8E736b2C28928D1EcAC0F5020d7A9');

  var erc1056Ropsten = Erc1056(rpcRopsten);
  var gasChangeOwnerErc = await erc1056Ropsten.estimateChangeOwner(
      'did:ethr:0x0c90C980568f65547E3F3523Da603f4621E90598',
      'did:ethr:0x14fb749193Ff374Af8ee4b763F4661943c7B7f99');
  var gasAddDelegateErc = await erc1056Ropsten.estimateAddDelegate(
      'did:ethr:0x0c90C980568f65547E3F3523Da603f4621E90598',
      'delegateType',
      'did:ethr:0x14fb749193Ff374Af8ee4b763F4661943c7B7f99');
  var gasRevokeDelegateErc = await erc1056Ropsten.estimateRevokeDelegate(
      'did:ethr:0x0c90C980568f65547E3F3523Da603f4621E90598',
      'delegateType',
      'did:ethr:0x14fb749193Ff374Af8ee4b763F4661943c7B7f99');
  var endpoint = 'https://hs-mittweida.de/endpoint';
  var gasSetAttributeErc = await erc1056Ropsten.estimateSetAttribute(
      'did:ethr:0x0c90C980568f65547E3F3523Da603f4621E90598',
      'service',
      endpoint);
  var gasRevokeAttributeErc = await erc1056Ropsten.estimateRevokeAttribute(
      'did:ethr:0x0c90C980568f65547E3F3523Da603f4621E90598',
      'service',
      endpoint);

  var etherscanRes = jsonDecode((await http.get(Uri.parse(
          'https://api.etherscan.io/api?module=gastracker&action=gasoracle&apikey=D48K393D61FXFZX6CRZSDUC2DVTS26N6SH')))
      .body);
  var safeGasPrice = EtherAmount.fromUnitAndValue(
          EtherUnit.gwei, etherscanRes['result']['SafeGasPrice'])
      .getValueInUnit(EtherUnit.ether);
  var proposeGasPrice = EtherAmount.fromUnitAndValue(
          EtherUnit.gwei, etherscanRes['result']['ProposeGasPrice'])
      .getValueInUnit(EtherUnit.ether);
  var fastGasPrice = EtherAmount.fromUnitAndValue(
          EtherUnit.gwei, etherscanRes['result']['FastGasPrice'])
      .getValueInUnit(EtherUnit.ether);

  var cryptoCmpRes = jsonDecode((await http.get(Uri.parse(
          'https://min-api.cryptocompare.com/data/price?fsym=ETH&tsyms=EUR')))
      .body);
  var ethEur = cryptoCmpRes['EUR'];

  print('Wechselkurs Ether-Euro: 1 ETH = $ethEur €');
  print('Function \t\t SafeGasPrice \t ProposeGasPrice \t FastGasPrice');
  print('Gas-Price (gwei) \t ${etherscanRes['result']['SafeGasPrice']} \t\t\t '
      '${etherscanRes['result']['ProposeGasPrice']} \t\t\t '
      '${etherscanRes['result']['FastGasPrice']}');
  print('----- Revocation-Contract -------');
  print(
      'Deploy \t\t\t\t ${(gasRopstenDeploy.toDouble() * safeGasPrice * ethEur).toStringAsFixed(2)} \t\t\t'
      ' ${(gasRopstenDeploy.toDouble() * proposeGasPrice * ethEur).toStringAsFixed(2)} \t\t\t'
      ' ${(gasRopstenDeploy.toDouble() * fastGasPrice * ethEur).toStringAsFixed(2)}');
  print(
      'Revoke \t\t\t\t ${(gasRopstenRevoke.toDouble() * safeGasPrice * ethEur).toStringAsFixed(2)} \t\t'
      '\t ${(gasRopstenRevoke.toDouble() * proposeGasPrice * ethEur).toStringAsFixed(2)} \t\t\t'
      ' ${(gasRopstenRevoke.toDouble() * fastGasPrice * ethEur).toStringAsFixed(2)}');
  print(
      'ChangeOwner \t\t ${(gasRopstenChange.toDouble() * safeGasPrice * ethEur).toStringAsFixed(2)} \t\t'
      '\t ${(gasRopstenChange.toDouble() * proposeGasPrice * ethEur).toStringAsFixed(2)} \t\t\t'
      ' ${(gasRopstenChange.toDouble() * fastGasPrice * ethEur).toStringAsFixed(2)}');
  print('------ ERC-1056 ----------');
  print(
      'ChangeOwner \t\t ${(gasChangeOwnerErc.toDouble() * safeGasPrice * ethEur).toStringAsFixed(2)} \t\t'
      '\t ${(gasChangeOwnerErc.toDouble() * proposeGasPrice * ethEur).toStringAsFixed(2)} \t\t\t'
      ' ${(gasChangeOwnerErc.toDouble() * fastGasPrice * ethEur).toStringAsFixed(2)}');
  print(
      'AddDelegate \t\t ${(gasAddDelegateErc.toDouble() * safeGasPrice * ethEur).toStringAsFixed(2)} \t\t'
      '\t ${(gasAddDelegateErc.toDouble() * proposeGasPrice * ethEur).toStringAsFixed(2)} \t\t\t'
      ' ${(gasAddDelegateErc.toDouble() * fastGasPrice * ethEur).toStringAsFixed(2)}');
  print(
      'RevokeDelegate \t\t ${(gasRevokeDelegateErc.toDouble() * safeGasPrice * ethEur).toStringAsFixed(2)} \t\t'
      '\t ${(gasRevokeDelegateErc.toDouble() * proposeGasPrice * ethEur).toStringAsFixed(2)} \t\t\t'
      ' ${(gasRevokeDelegateErc.toDouble() * fastGasPrice * ethEur).toStringAsFixed(2)}');
  print(
      'SetAttribute \t\t ${(gasSetAttributeErc.toDouble() * safeGasPrice * ethEur).toStringAsFixed(2)} \t\t'
      '\t ${(gasSetAttributeErc.toDouble() * proposeGasPrice * ethEur).toStringAsFixed(2)} \t\t\t'
      ' ${(gasSetAttributeErc.toDouble() * fastGasPrice * ethEur).toStringAsFixed(2)}');
  print(
      'RevokeAttribute \t ${(gasRevokeAttributeErc.toDouble() * safeGasPrice * ethEur).toStringAsFixed(2)} \t\t'
      '\t ${(gasRevokeAttributeErc.toDouble() * proposeGasPrice * ethEur).toStringAsFixed(2)} \t\t\t'
      ' ${(gasRevokeAttributeErc.toDouble() * fastGasPrice * ethEur).toStringAsFixed(2)}');
}
