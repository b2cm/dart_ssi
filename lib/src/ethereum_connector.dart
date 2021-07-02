import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart';
import 'package:web3dart/crypto.dart';
import 'package:web3dart/web3dart.dart';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_ssi_wallet/flutter_ssi_wallet.dart';
import 'package:flutter_ssi_wallet/src/ethereum_connector.dart';

/// Dart representation of Ethereums ERC-1056 SmartContract.
class Erc1056 {
  final String abi =
      '[{"constant":false,"inputs":[{"name":"identity","type":"address"},'
      '{"name":"name","type":"bytes32"},{"name":"value","type":"bytes"}],'
      '"name":"revokeAttribute","outputs":[],"payable":false,"stateMutability":'
      '"nonpayable","type":"function"},{"constant":true,"inputs":'
      '[{"name":"","type":"address"}],"name":"owners","outputs":'
      '[{"name":"","type":"address"}],"payable":false,"stateMutability":'
      '"view","type":"function"},{"constant":true,"inputs":'
      '[{"name":"","type":"address"},{"name":"","type":"bytes32"},'
      '{"name":"","type":"address"}],"name":"delegates","outputs":'
      '[{"name":"","type":"uint256"}],"payable":false,"stateMutability":'
      '"view","type":"function"},{"constant":false,"inputs":[{"name":'
      '"identity","type":"address"},{"name":"sigV","type":"uint8"},'
      '{"name":"sigR","type":"bytes32"},{"name":"sigS","type":"bytes32"},'
      '{"name":"name","type":"bytes32"},{"name":"value","type":"bytes"},'
      '{"name":"validity","type":"uint256"}],"name":"setAttributeSigned",'
      '"outputs":[],"payable":false,"stateMutability":"nonpayable","type":'
      '"function"},{"constant":false,"inputs":[{"name":"identity","type":'
      '"address"},{"name":"sigV","type":"uint8"},{"name":"sigR","type":'
      '"bytes32"},{"name":"sigS","type":"bytes32"},{"name":"newOwner","type":'
      '"address"}],"name":"changeOwnerSigned","outputs":[],"payable":false,'
      '"stateMutability":"nonpayable","type":"function"},{"constant":true,'
      '"inputs":[{"name":"identity","type":"address"},{"name":"delegateType",'
      '"type":"bytes32"},{"name":"delegate","type":"address"}],"name":'
      '"validDelegate","outputs":[{"name":"","type":"bool"}],"payable":false,'
      '"stateMutability":"view","type":"function"},{"constant":true,"inputs":'
      '[{"name":"","type":"address"}],"name":"nonce","outputs":[{"name":"",'
      '"type":"uint256"}],"payable":false,"stateMutability":"view","type":'
      '"function"},{"constant":false,"inputs":[{"name":"identity","type":'
      '"address"},{"name":"name","type":"bytes32"},{"name":"value","type":'
      '"bytes"},{"name":"validity","type":"uint256"}],"name":"setAttribute",'
      '"outputs":[],"payable":false,"stateMutability":"nonpayable","type":'
      '"function"},{"constant":false,"inputs":[{"name":"identity","type":'
      '"address"},{"name":"delegateType","type":"bytes32"},{"name":"delegate",'
      '"type":"address"}],"name":"revokeDelegate","outputs":[],"payable":false,'
      '"stateMutability":"nonpayable","type":"function"},{"constant":true,'
      '"inputs":[{"name":"identity","type":"address"}],"name":"identityOwner",'
      '"outputs":[{"name":"","type":"address"}],"payable":false,'
      '"stateMutability":"view","type":"function"},{"constant":false,"inputs":'
      '[{"name":"identity","type":"address"},{"name":"sigV","type":"uint8"},'
      '{"name":"sigR","type":"bytes32"},{"name":"sigS","type":"bytes32"},'
      '{"name":"delegateType","type":"bytes32"},{"name":"delegate","type":'
      '"address"}],"name":"revokeDelegateSigned","outputs":[],"payable":false,'
      '"stateMutability":"nonpayable","type":"function"},{"constant":false,'
      '"inputs":[{"name":"identity","type":"address"},{"name":"sigV","type":'
      '"uint8"},{"name":"sigR","type":"bytes32"},{"name":"sigS","type":'
      '"bytes32"},{"name":"delegateType","type":"bytes32"},{"name":"delegate",'
      '"type":"address"},{"name":"validity","type":"uint256"}],"name":'
      '"addDelegateSigned","outputs":[],"payable":false,"stateMutability":'
      '"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":'
      '"identity","type":"address"},{"name":"delegateType","type":"bytes32"},'
      '{"name":"delegate","type":"address"},{"name":"validity","type":'
      '"uint256"}],"name":"addDelegate","outputs":[],"payable":false,'
      '"stateMutability":"nonpayable","type":"function"},{"constant":false,'
      '"inputs":[{"name":"identity","type":"address"},{"name":"sigV","type":'
      '"uint8"},{"name":"sigR","type":"bytes32"},{"name":"sigS","type":'
      '"bytes32"},{"name":"name","type":"bytes32"},{"name":"value","type":'
      '"bytes"}],"name":"revokeAttributeSigned","outputs":[],"payable":false,'
      '"stateMutability":"nonpayable","type":"function"},{"constant":false,'
      '"inputs":[{"name":"identity","type":"address"},{"name":"newOwner",'
      '"type":"address"}],"name":"changeOwner","outputs":[],"payable":false,'
      '"stateMutability":"nonpayable","type":"function"},{"constant":true,'
      '"inputs":[{"name":"","type":"address"}],"name":"changed","outputs":'
      '[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view",'
      '"type":"function"},{"anonymous":false,"inputs":[{"indexed":true,"name":'
      '"identity","type":"address"},{"indexed":false,"name":"owner","type":'
      '"address"},{"indexed":false,"name":"previousChange","type":"uint256"}],'
      '"name":"DIDOwnerChanged","type":"event"},{"anonymous":false,"inputs":'
      '[{"indexed":true,"name":"identity","type":"address"},{"indexed":false,'
      '"name":"delegateType","type":"bytes32"},{"indexed":false,"name":'
      '"delegate","type":"address"},{"indexed":false,"name":"validTo",'
      '"type":"uint256"},{"indexed":false,"name":"previousChange","type":'
      '"uint256"}],"name":"DIDDelegateChanged","type":"event"},{"anonymous":'
      'false,"inputs":[{"indexed":true,"name":"identity","type":"address"},'
      '{"indexed":false,"name":"name","type":"bytes32"},{"indexed":false,'
      '"name":"value","type":"bytes"},{"indexed":false,"name":"validTo","type":'
      '"uint256"},{"indexed":false,"name":"previousChange","type":"uint256"}],'
      '"name":"DIDAttributeChanged","type":"event"}]';

  late DeployedContract _erc1056contract;
  late Web3Client web3Client;
  late EthereumAddress contractAddress;
  late Utf8Codec _utf8;
  late String networkName;
  late int chainId;

  final _numbersToNames = {
    1: 'mainnet',
    3: 'ropsten',
    4: 'rinkeby',
    5: 'goerli',
    42: 'kovan'
  };
  final _namesToNumbers = {
    'mainnet': 1,
    'ropsten': 3,
    'rinkeby': 4,
    'goerli': 5,
    'kovan': 42
  };

  Erc1056(String rpcUrl,
      {dynamic networkNameOrId = 1,
      String contractName: 'EthereumDIDRegistry',
      //String contractAddress: '0xdca7ef03e98e0dc2b855be647c39abe984fcf21b'
      String contractAddress: '0xA46f0bB111fF7186505AB3091b28412d689aF512'
      }) {
    this.contractAddress = EthereumAddress.fromHex(contractAddress);

    _utf8 = Utf8Codec(allowMalformed: true);

    _erc1056contract = DeployedContract(
        ContractAbi.fromJson(abi, contractName), this.contractAddress);

    web3Client = Web3Client(rpcUrl, Client());

    if (networkNameOrId.runtimeType == int) {
      chainId = networkNameOrId;
      if (_numbersToNames.containsKey(networkNameOrId))
        networkName = _numbersToNames[networkNameOrId]!;
      else
        networkName = bytesToHex(intToBytes(BigInt.from(networkNameOrId)));
    } else if (networkNameOrId.runtimeType == String) {
      networkName = networkNameOrId;
      if (_namesToNumbers.containsKey(networkNameOrId))
        chainId = _namesToNumbers[networkNameOrId]!;
      else
        chainId = 1337;
    } else {
      throw Exception('Unexpected Runtime-Type for networkNameOrId');
    }
  }

  /// Request the current owner (its did) for identity [did].
  Future<String> identityOwner(String did) async {
    if (!_matchesExpectedDid(did))
      throw Exception('Information about $did cannot be found in this network');
    var identityOwnerFunction = _erc1056contract.function('identityOwner');
    var owner = await web3Client.call(
        contract: _erc1056contract,
        function: identityOwnerFunction,
        params: [_didToAddress(did)]);
    var ownerAddress = owner.first as EthereumAddress;
    return _addressToDid(ownerAddress);
  }

  Future<void> changeOwner(
      String privateKeyFrom, String identityDid, String newDid) async {
    if (!_matchesExpectedDid(identityDid))
      throw Exception(
          'Information about $identityDid do not belong to this network');
    if (!_matchesExpectedDid(newDid))
      throw Exception(
          'Information about $newDid do not belong to this network');
    var changeOwnerFunction = _erc1056contract.function('changeOwner');

    await web3Client.sendTransaction(
        EthPrivateKey.fromHex(privateKeyFrom),
        Transaction.callContract(
            contract: _erc1056contract,
            function: changeOwnerFunction,
            parameters: [_didToAddress(identityDid), _didToAddress(newDid)]),
        chainId: chainId);
  }

  Future<void> changeOwnerSigned( //Credentials cred,
      String privateKeyFrom,
      String addressFrom,
      String addressTo,
      String addressSpender,
      String privateKeySpender,
      ) async {

    var changeOwnerSignedFunction = _erc1056contract.function(
        'changeOwnerSigned');

    String nonceCredential = nonce(addressFrom).toString();

    //Create Hash to sign the message
    var contractAddressString = contractAddress.toString();
    List<String?> list = [
      '0x19',
      '0x0',
      contractAddressString,
      nonceCredential,
      addressFrom,
      'changeOwner',
      addressTo
    ];
    List<String> filteredList = _filter(list); // New list
    String filteredListString = filteredList.join(', ');

    Uint8List messageHash;
    messageHash = keccak256(_uint8ListFromList(utf8.encode(filteredListString)));

    //Sign the hash and privateKey
    var privateKeyUtf8 = Utf8Encoder().convert(privateKeyFrom, 51);

    MsgSignature messageSignature = sign(messageHash, privateKeyUtf8);

    Uint8List pubKey_privateKeyBytesToPublic;
    pubKey_privateKeyBytesToPublic = privateKeyBytesToPublic(privateKeyUtf8);

    bool isValidSignatureBool = isValidSignature(
        messageHash, messageSignature, pubKey_privateKeyBytesToPublic);

    if (isValidSignatureBool == true)
      {
        BigInt msgV    = BigInt.from(messageSignature.v);
        Uint8List msgR = unsignedIntToBytes(messageSignature.r);
        Uint8List msgS = unsignedIntToBytes(messageSignature.s);

      //Call of the changeOwnerSignedFunction with the raw data
      Transaction tx = Transaction.callContract(
          contract: _erc1056contract,
          function: changeOwnerSignedFunction,
          parameters: [
            _didToAddress(addressFrom),
            msgV, //messageSignature.v,
            msgR, //messageSignature.r,
            msgS, //messageSignature.s,
            _didToAddress(addressSpender)
          ]);
      await web3Client.sendTransaction(EthPrivateKey.fromHex(privateKeySpender), tx,
          chainId: chainId);

    }
    else {
    }

  }

  Future<void> setAttribute(
      String privateKeyFrom, String identityDid, String name, String value,
      {int validity: 86400}) async {
    if (validity <= 0) throw Exception('negative validity');
    if (!_matchesExpectedDid(identityDid))
      throw Exception(
          'Information about $identityDid do not belong to this network');
    var setAttributeFunction = _erc1056contract.function('setAttribute');
    var valueList = Uint8List.fromList(_utf8.encode(value));
    Transaction tx = Transaction.callContract(
        contract: _erc1056contract,
        function: setAttributeFunction,
        parameters: [
          _didToAddress(identityDid),
          _to32ByteUtf8(name),
          valueList,
          BigInt.from(validity)
        ]);

    await web3Client.sendTransaction(EthPrivateKey.fromHex(privateKeyFrom), tx,
        chainId: chainId);
  }

  Future<void> revokeAttribute(String privateKeyFrom, String identityDid,
      String name, String value) async {
    if (!_matchesExpectedDid(identityDid))
      throw Exception(
          'Information about $identityDid do not belong to this network');
    var revokeAttributeFunction = _erc1056contract.function('revokeAttribute');
    var nameList = _to32ByteUtf8(name);
    var valueList = Uint8List.fromList(_utf8.encode(value));

    Transaction tx = Transaction.callContract(
        contract: _erc1056contract,
        function: revokeAttributeFunction,
        parameters: [_didToAddress(identityDid), nameList, valueList]);

    await web3Client.sendTransaction(EthPrivateKey.fromHex(privateKeyFrom), tx,
        chainId: chainId);
  }

  Future<void> addDelegate(String privateKeyFrom, String identityDid,
      String delegateType, String delegateDid,
      {int validity: 86400}) async {
    if (validity <= 0) throw Exception('negative validity');
    if (!_matchesExpectedDid(identityDid))
      throw Exception(
          'Information about $identityDid do not belong to this network');
    var addDelegateFunction = _erc1056contract.function('addDelegate');
    Transaction tx = Transaction.callContract(
        contract: _erc1056contract,
        function: addDelegateFunction,
        parameters: [
          _didToAddress(identityDid),
          _to32ByteUtf8(delegateType),
          _didToAddress(delegateDid),
          BigInt.from(validity)
        ]);

    await web3Client.sendTransaction(EthPrivateKey.fromHex(privateKeyFrom), tx,
        chainId: chainId);
  }

  Future<void> revokeDelegate(String privateKeyFrom, String identityDid,
      String delegateType, String delegateDid) async {
    if (!_matchesExpectedDid(identityDid))
      throw Exception(
          'Information about $identityDid do not belong to this network');
    if (!_matchesExpectedDid(delegateDid))
      throw Exception(
          'Information about $delegateDid do not belong to this network');
    var revokeDelegateFunction = _erc1056contract.function('revokeDelegate');
    Transaction tx = Transaction.callContract(
        contract: _erc1056contract,
        function: revokeDelegateFunction,
        parameters: [
          _didToAddress(identityDid),
          _to32ByteUtf8(delegateType),
          _didToAddress(delegateDid)
        ]);

    await web3Client.sendTransaction(EthPrivateKey.fromHex(privateKeyFrom), tx,
        chainId: chainId);
  }

  Future<bool?> validDelegate(
      String identityDid, String delegateType, String delegateDid) async {
    if (!_matchesExpectedDid(identityDid))
      throw Exception(
          'Information about $identityDid do not belong to this network');
    if (!_matchesExpectedDid(delegateDid))
      throw Exception(
          'Information about $delegateDid do not belong to this network');
    var validDelegateFunction = _erc1056contract.function('validDelegate');
    var valid = await web3Client.call(
        contract: _erc1056contract,
        function: validDelegateFunction,
        params: [
          _didToAddress(identityDid),
          _to32ByteUtf8(delegateType),
          _didToAddress(delegateDid)
        ]);

    return valid.first as bool?;
  }

  Future<BigInt?> changed(String identityDid) async {
    if (!_matchesExpectedDid(identityDid))
      throw Exception(
          'Information about $identityDid do not belong to this network');
    var changedFunction = _erc1056contract.function('changed');
    var changedBlock = await web3Client.call(
        contract: _erc1056contract,
        function: changedFunction,
        params: [_didToAddress(identityDid)]);
    return changedBlock.first as BigInt?;
  }

  Future<BigInt?> nonce(String identityDid) async {
    if (!_matchesExpectedDid(identityDid))
      throw Exception(
          'Information about $identityDid do not belong to this network');
    var nonceFunction = _erc1056contract.function('nonce');
    var nonceValue = await web3Client.call(
        contract: _erc1056contract,
        function: nonceFunction,
        params: [_didToAddress(identityDid)]);

    return nonceValue.first as BigInt?;
  }

  ///Collects all data from contract log for [identityDid].
  ///
  /// It returns a map containing the keys owners, attributes and delegates. Behind owners-key
  /// is a List<String> with the hex-representation of all the ethereum addresses that
  /// controlled this identity in the past. attributes and delegates gives a Map<String, List<String>>
  /// mapping the delegate-type or attribute-name to their values.
  Future<Map<String, dynamic>> collectEventData(String identityDid) async {
    if (!_matchesExpectedDid(identityDid))
      throw Exception(
          'Information about $identityDid do not belong to this network');
    var didOwnerChangedEvent = _erc1056contract.event('DIDOwnerChanged');
    var didDelegateChangedEvent = _erc1056contract.event('DIDDelegateChanged');
    var didAttributeChangedEvent =
        _erc1056contract.event('DIDAttributeChanged');
    List<String> owners = [];
    var delegates = Map<String, List<String>>();
    var attributes = Map<String, List<String>>();
    List<String> revokedAttributes = [];
    int secNow = (DateTime.now().millisecondsSinceEpoch ~/ 1000);

    var lastChange = await changed(identityDid);

    while (lastChange != BigInt.zero) {
      var logs = await web3Client.getLogs(FilterOptions(
          fromBlock: BlockNum.exact(lastChange!.toInt()),
          toBlock: BlockNum.exact(lastChange.toInt()),
          topics: [
            [
              bytesToHex(didOwnerChangedEvent.signature, include0x: true),
              bytesToHex(didDelegateChangedEvent.signature, include0x: true),
              bytesToHex(didAttributeChangedEvent.signature, include0x: true)
            ],
            ['0x${_didToAddress(identityDid).hexNo0x.padLeft(64, '0')}']
          ]));
      List<BigInt?> listOfPreviousChanges = [];

      await Future.forEach(logs, (dynamic event) async {
        if (event.topics.first ==
            bytesToHex(didOwnerChangedEvent.signature, include0x: true)) {
          var decodedEvent =
              didOwnerChangedEvent.decodeResults(event.topics, event.data);
          var owner = decodedEvent[1] as EthereumAddress;
          var previousChange = decodedEvent[2] as BigInt?;

          listOfPreviousChanges.add(previousChange);
          owners.add(_addressToDid(owner));
        } else if (event.topics.first ==
            bytesToHex(didAttributeChangedEvent.signature, include0x: true)) {
          var decodedEvent =
              didAttributeChangedEvent.decodeResults(event.topics, event.data);
          var name = decodedEvent[1] as Uint8List;
          var value = decodedEvent[2] as Uint8List;
          var validTo = decodedEvent[3] as BigInt;
          var previousChange = decodedEvent[4] as BigInt?;
          var nameStr = _bytes32ToString(name);
          var valueStr = _utf8.decode(value);

          listOfPreviousChanges.add(previousChange);

          if (validTo < BigInt.from(secNow)) {
            revokedAttributes.add('$nameStr-$valueStr');
          } else {
            if (!revokedAttributes.contains('$nameStr-$valueStr')) {
              if (attributes.containsKey(nameStr) &&
                  (!attributes[nameStr]!.contains(valueStr))) {
                attributes[nameStr]!.add(valueStr);
              } else {
                List<String> tmp = [];
                tmp.add(valueStr);
                attributes[nameStr] = tmp;
              }
            }
          }
        } else if (event.topics.first ==
            bytesToHex(didDelegateChangedEvent.signature, include0x: true)) {
          var decodedEvent =
              didDelegateChangedEvent.decodeResults(event.topics, event.data);
          var delegateType = decodedEvent[1] as Uint8List;
          var delegate = decodedEvent[2] as EthereumAddress;
          var previousChange = decodedEvent[4] as BigInt?;
          var delegateTypeString = _bytes32ToString(delegateType);

          listOfPreviousChanges.add(previousChange);

          var validDelegate = await this.validDelegate(
              identityDid, delegateTypeString, _addressToDid(delegate));
          if (validDelegate!) {
            if (delegates.containsKey(delegateTypeString) &&
                (!delegates[delegateTypeString]!
                    .contains(_addressToDid(delegate)))) {
              delegates[delegateTypeString]!.add(_addressToDid(delegate));
            } else {
              List<String> tmpList = [];
              tmpList.add(_addressToDid(delegate));
              delegates[delegateTypeString] = tmpList;
            }
          }
        } else {
          throw Exception('Unknown Event-Signature ${event.topics.first}');
        }
      });

      listOfPreviousChanges.sort();
      BigInt? lastChangeNew = listOfPreviousChanges.last;
      for (int i = listOfPreviousChanges.length - 1; i >= 0; i--) {
        if (lastChangeNew != lastChange &&
            (!(listOfPreviousChanges[i]! < lastChangeNew!))) {
          lastChangeNew = listOfPreviousChanges[i];
        }
      }

      if (lastChangeNew == lastChange)
        break;
      else
        lastChange = lastChangeNew;
    }

    var eventData = Map<String, dynamic>();
    eventData['owners'] = owners;
    eventData['attributes'] = attributes;
    eventData['delegates'] = delegates;
    return eventData;
  }

  /// Returns a minimal did-document for [identityDid], only with information about the current identity owner
  Future<String> didDocument(String identityDid) async {
    var owner = await identityOwner(identityDid);
    Map<String, dynamic> doc = {
      '@context': [
        "https://www.w3.org/ns/did/v1",
        "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld"
      ],
      "id": identityDid,
      "verificationMethod": [
        {
          "id": '$owner#controller',
          "type": "EcdsaSecp256k1RecoveryMethod2020",
          "controller": owner,
          "blockchainAccountId": _didToAddress(owner).hexEip55
        }
      ],
      "authentication": ['$owner#controller']
    };
    return jsonEncode(doc);
  }

  bool _matchesExpectedDid(String did) {
    var addr = _didToAddress(did);
    String expectedName = 'did:ethr:$networkName:${addr.hexEip55}';
    String expectedId =
        'did:ethr:${bytesToHex(intToBytes(BigInt.from(chainId)))}:${addr.hexEip55}';
    if (chainId == 1) {
      String expectedName2 = 'did:ethr:${addr.hexEip55}';
      if (!(did == expectedId || did == expectedName || did == expectedName2))
        return false;
      else
        return true;
    } else {
      if (!(did == expectedId || did == expectedName))
        return false;
      else
        return true;
    }
  }

  Uint8List _to32ByteUtf8(String name) {
    var nameUtf8 = _utf8.encode(name);
    if (nameUtf8.length > 32) throw Exception('name is too long');
    var nameList = Uint8List(32);
    for (int i = 0; i < nameUtf8.length; i++) {
      nameList[i] = nameUtf8[i];
    }
    return nameList;
  }

  String _bytes32ToString(Uint8List value) {
    List<int> nameUnpadded = [];
    for (int i = 0; i < value.length; i++) {
      if (value[i] != 0) nameUnpadded.add(value[i]);
    }
    return _utf8.decode(nameUnpadded);
  }

  String _addressToDid(EthereumAddress address) {
    if (networkName == 'mainnet')
      return 'did:ethr:${address.hexEip55}';
    else
      return 'did:ethr:$networkName:${address.hexEip55}';
  }
}

/// Represents an ethereum-smartcontract to revoke credentials.
class RevocationRegistry {
  String _abi = '[{"inputs": [],"stateMutability": "nonpayable","type": '
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

  String _bytecode =
      '608060405234801561001057600080fd5b50336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555043600181905550610396806100676000396000f3fe608060405234801561001057600080fd5b506004361061004c5760003560e01c806374a8f103146100515780638da5cb5b14610095578063a6f9dae1146100c9578063f905c15a1461010d575b600080fd5b6100936004803603602081101561006757600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505061012b565b005b61009d610232565b604051808273ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b61010b600480360360208110156100df57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610256565b005b61011561035a565b6040518082815260200191505060405180910390f35b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146101ec576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260088152602001807f6e6f206f776e657200000000000000000000000000000000000000000000000081525060200191505060405180910390fd5b8073ffffffffffffffffffffffffffffffffffffffff167fa4e30c0434a0fd06abd5093463a1a4a0e8886a6b803f82bc06e56d799668099960405160405180910390a250565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610317576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260088152602001807f6e6f206f776e657200000000000000000000000000000000000000000000000081525060200191505060405180910390fd5b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b6001548156fea2646970667358221220d3b1720f8ebb198a64a353f3ba110eb4f71210c4af5b56dee1be962355aade1b64736f6c63430007050033';

  late Web3Client _web3Client;
  late DeployedContract _contract;
  late int _chainId;

  RevocationRegistry(String rpcUrl, {String? contractAddress, chainId = 1}) {
    _web3Client = Web3Client(rpcUrl, Client());
    _chainId = chainId;

    if (contractAddress != null) {
      _contract = DeployedContract(
          ContractAbi.fromJson(_abi, 'RevocationRegistry'),
          EthereumAddress.fromHex(contractAddress));
    }
  }

  Future<String> deploy(String privateKeyFrom) async {
    var creds = EthPrivateKey.fromHex(privateKeyFrom);
    var address = await creds.extractAddress();
    var tx = Transaction(
        from: address,
        data: hexToBytes(_bytecode),
        gasPrice: EtherAmount.fromUnitAndValue(EtherUnit.gwei, 20),
        maxGas: 474455);

    var res = await _web3Client.sendTransaction(creds, tx, chainId: _chainId);
    if (res == '') {
      return '';
    }
    var receipt;
    try {
      receipt = await _web3Client.getTransactionReceipt(res);
    } catch (e) {}

    while (receipt == null) {
      sleep(Duration(seconds: 1));
      try {
        receipt = await _web3Client.getTransactionReceipt(res);
      } catch (e) {}
    }

    _contract = DeployedContract(
        ContractAbi.fromJson(_abi, 'RevocationRegistry'),
        receipt.contractAddress!);
    return receipt.contractAddress!.hexEip55;
  }

  Future<void> revoke(String privateKeyFrom, String credDidToRevoke) async {
    var revokeFunction = _contract.function('revoke');
    var tx = Transaction.callContract(
        contract: _contract,
        function: revokeFunction,
        parameters: [_didToAddress(credDidToRevoke)]);
    await _web3Client.sendTransaction(EthPrivateKey.fromHex(privateKeyFrom), tx,
        chainId: _chainId);
  }

  /// Returns the block number of the block in which the contract was deployed.
  Future<BigInt?> deployed() async {
    var deployedFunction = _contract.function('deployed');
    var res = await _web3Client
        .call(contract: _contract, function: deployedFunction, params: []);

    return res.first as BigInt?;
  }

  Future<bool> isRevoked(String credentialDid) async {
    var revokedEvent = _contract.event('RevokedEvent');
    var revEventSig = bytesToHex(revokedEvent.signature);
    var deployedBlock = await deployed();
    var logs = await _web3Client.getLogs(FilterOptions(
        address: _contract.address,
        fromBlock: BlockNum.exact(deployedBlock!.toInt()),
        topics: [
          ['0x${revEventSig.padLeft(64, '0')}'],
          ['0x${_didToAddress(credentialDid).hexNo0x.padLeft(64, '0')}']
        ]));

    return logs.isNotEmpty;
  }

  Future<void> changeOwner(String privateKeyFrom, String didNewOwner) async {
    var changeOwnerFunction = _contract.function('changeOwner');
    var tx = Transaction.callContract(
        contract: _contract,
        function: changeOwnerFunction,
        parameters: [_didToAddress(didNewOwner)]);
    await _web3Client.sendTransaction(EthPrivateKey.fromHex(privateKeyFrom), tx,
        chainId: _chainId);
  }
}

EthereumAddress _didToAddress(String did) {
  var splitted = did.split(':');
  return EthereumAddress.fromHex(splitted.last);
}

Uint8List _uint8ListFromList(List<int> data) {
  if (data is Uint8List) return data;
  return Uint8List.fromList(data);
}
//Function Filter null
List<String> _filter(List<String?> input) {
  input.removeWhere((e) => e == null);
  return List<String>.from(input);
}
