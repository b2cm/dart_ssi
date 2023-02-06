import 'dart:async';
import 'dart:io';

import 'package:http/http.dart';
import 'package:web3dart/crypto.dart';
import 'package:web3dart/json_rpc.dart';
import 'package:web3dart/web3dart.dart';

/// Represents an ethereum-smartcontract to revoke credentials.
class RevocationRegistry {
  final String _abi = '[{"inputs": [],"stateMutability": "nonpayable","type": '
      '"constructor"},{"anonymous": false,"inputs": [{"indexed": true,'
      '"internalType": "address","name": "credential","type": "address"}],'
      '"name": "RevokedEvent","type": "event"},{"inputs": [{"internalType":'
      '"address","name": "_newOwner","type": "address"}],"name": "changeOwner",'
      '"outputs": [],"stateMutability": "nonpayable","type": "function"},'
      '{"inputs": [],"name": "deployed","outputs": [{"internalType": "uint256",'
      '"name": "","type": "uint256"}],"stateMutability": "view","type": '
      '"function"},{"inputs": [],"name": "owner","outputs": [{"internalType": '
      '"address","name": "","type": "address"}],"stateMutability": "view",'
      '"type": "function"},{"inputs": [{"internalType": "address","name": "'
      '_credential","type": "address"}],"name": "revoke","outputs": [],'
      '"stateMutability": "nonpayable","type": "function"}]';

  final String _bytecode =
      '608060405234801561001057600080fd5b50336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555043600181905550610396806100676000396000f3fe608060405234801561001057600080fd5b506004361061004c5760003560e01c806374a8f103146100515780638da5cb5b14610095578063a6f9dae1146100c9578063f905c15a1461010d575b600080fd5b6100936004803603602081101561006757600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505061012b565b005b61009d610232565b604051808273ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b61010b600480360360208110156100df57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610256565b005b61011561035a565b6040518082815260200191505060405180910390f35b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146101ec576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260088152602001807f6e6f206f776e657200000000000000000000000000000000000000000000000081525060200191505060405180910390fd5b8073ffffffffffffffffffffffffffffffffffffffff167fa4e30c0434a0fd06abd5093463a1a4a0e8886a6b803f82bc06e56d799668099960405160405180910390a250565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610317576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260088152602001807f6e6f206f776e657200000000000000000000000000000000000000000000000081525060200191505060405180910390fd5b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b6001548156fea2646970667358221220d3b1720f8ebb198a64a353f3ba110eb4f71210c4af5b56dee1be962355aade1b64736f6c63430007050033';

  late Web3Client web3Client;
  late DeployedContract _contract;
  late int _chainId;
  late JsonRPC _rpc;

  RevocationRegistry(String rpcUrl, {String? contractAddress, chainId = 1}) {
    web3Client = Web3Client(rpcUrl, Client());
    _chainId = chainId;
    _rpc = JsonRPC(rpcUrl, Client());

    if (contractAddress != null) {
      setContract(contractAddress);
    }
  }

  Future<String> deploy(String privateKeyFrom) async {
    var creds = EthPrivateKey.fromHex(privateKeyFrom);
    var address = creds.address;
    var tx = Transaction(
        from: address,
        data: hexToBytes(_bytecode),
        gasPrice: EtherAmount.fromInt(EtherUnit.gwei, 20),
        maxGas: 474455);

    var res = await web3Client.sendTransaction(creds, tx, chainId: _chainId);
    if (res == '') {
      return '';
    }
    TransactionReceipt? receipt;
    try {
      receipt = await web3Client.getTransactionReceipt(res);
    } catch (e) {
      print('Transaction not in chain');
    }

    while (receipt == null) {
      sleep(Duration(seconds: 1));
      try {
        receipt = await web3Client.getTransactionReceipt(res);
      } catch (e) {
        print('Transaction not in chain');
      }
    }

    _contract = DeployedContract(
        ContractAbi.fromJson(_abi, 'RevocationRegistry'),
        receipt.contractAddress!);
    return receipt.contractAddress!.hexEip55;
  }

  Future<BigInt> estimateGasDeploy(String from) async {
    return web3Client.estimateGas(
        data: hexToBytes(_bytecode), sender: EthereumAddress.fromHex(from));
  }

  Future<void> revoke(String privateKeyFrom, String credDidToRevoke) async {
    var revokeFunction = _contract.function('revoke');
    var tx = Transaction.callContract(
        contract: _contract,
        function: revokeFunction,
        parameters: [_didToAddress(credDidToRevoke)]);
    await web3Client.sendTransaction(EthPrivateKey.fromHex(privateKeyFrom), tx,
        chainId: _chainId);
  }

  Future<BigInt> estimateRevoke(String fromAddress, String credDidToRevoke) {
    var revokeFunction = _contract.function('revoke');
    var tx = Transaction.callContract(
        contract: _contract,
        function: revokeFunction,
        parameters: [_didToAddress(credDidToRevoke)]);
    return web3Client.estimateGas(
        sender: EthereumAddress.fromHex(fromAddress),
        data: tx.data,
        to: _contract.address);
  }

  /// Returns the block number of the block in which the contract was deployed.
  Future<BigInt?> deployed() async {
    var deployedFunction = _contract.function('deployed');
    var res = await web3Client
        .call(contract: _contract, function: deployedFunction, params: []);

    return res.first as BigInt?;
  }

  Future<bool> isRevoked(String credentialDid) async {
    var revokedEvent = _contract.event('RevokedEvent');
    var revEventSig = bytesToHex(revokedEvent.signature);
    var deployedBlock = await deployed();
    var logs = await web3Client.getLogs(FilterOptions(
        address: _contract.address,
        fromBlock: BlockNum.exact(deployedBlock!.toInt()),
        topics: [
          ['0x${revEventSig.padLeft(64, '0')}'],
          ['0x${_didToAddress(credentialDid).hexNo0x.padLeft(64, '0')}']
        ]));

    return logs.isNotEmpty;
  }

  Future<DateTime> revocationTimestamp(String credentialDid) async {
    var revokedEvent = _contract.event('RevokedEvent');
    var revEventSig = bytesToHex(revokedEvent.signature);
    var deployedBlock = await deployed();
    var logs = await web3Client.getLogs(FilterOptions(
        address: _contract.address,
        fromBlock: BlockNum.exact(deployedBlock!.toInt()),
        topics: [
          ['0x${revEventSig.padLeft(64, '0')}'],
          ['0x${_didToAddress(credentialDid).hexNo0x.padLeft(64, '0')}']
        ]));

    if (logs.isNotEmpty) {
      var firstLog = logs.first;
      var res = await _rpc.call('eth_getBlockByNumber', [
        bytesToHex(intToBytes(BigInt.from(firstLog.blockNum!)),
            include0x: true),
        false
      ]);
      return DateTime.fromMillisecondsSinceEpoch(
          hexToDartInt(res.result['timestamp']) * 1000);
    } else {
      throw Exception('Credential was not revoked');
    }
  }

  Future<void> changeOwner(String privateKeyFrom, String didNewOwner) async {
    var changeOwnerFunction = _contract.function('changeOwner');
    var tx = Transaction.callContract(
        contract: _contract,
        function: changeOwnerFunction,
        parameters: [_didToAddress(didNewOwner)]);
    await web3Client.sendTransaction(EthPrivateKey.fromHex(privateKeyFrom), tx,
        chainId: _chainId);
  }

  void setContract(String contractAddress) {
    _contract = DeployedContract(
        ContractAbi.fromJson(_abi, 'RevocationRegistry'),
        EthereumAddress.fromHex(contractAddress));
  }

  Future<BigInt> estimateChangeOwner(String from, String didNewOwner) {
    var changeOwnerFunction = _contract.function('changeOwner');
    var tx = Transaction.callContract(
        contract: _contract,
        function: changeOwnerFunction,
        parameters: [_didToAddress(didNewOwner)]);
    return web3Client.estimateGas(
        sender: EthereumAddress.fromHex(from),
        data: tx.data,
        to: _contract.address);
  }
}

EthereumAddress _didToAddress(String did) {
  var splitted = did.split(':');
  return EthereumAddress.fromHex(splitted.last);
}
