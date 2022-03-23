import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_web3/crypto.dart';
import 'package:dart_web3/dart_web3.dart';
import 'package:http/http.dart';

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

  get numbersToNames => _numbersToNames;
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
      String contractAddress: '0xdca7ef03e98e0dc2b855be647c39abe984fcf21b'}) {
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

  Future<String> changeOwnerSigned(String privateKeyFrom, String identityDid,
      String newDid, MsgSignature signature) async {
    var changeOwnerSignedFunction =
        _erc1056contract.function('changeOwnerSigned');

    var txHash = await web3Client.sendTransaction(
        EthPrivateKey.fromHex(privateKeyFrom),
        Transaction.callContract(
          contract: _erc1056contract,
          function: changeOwnerSignedFunction,
          parameters: [
            _didToAddress(identityDid),
            BigInt.from(signature.v),
            unsignedIntToBytes(signature.r),
            unsignedIntToBytes(signature.s),
            _didToAddress(newDid),
          ],
          // maxGas: 76853
        ),
        chainId: chainId);
    return txHash;
  }

  Future<MsgSignature> signOwnerChange(
    String privateKeyFrom,
    String identityDid,
    String newDid,
  ) async {
    var privateKey = EthPrivateKey.fromHex(privateKeyFrom).privateKey;
    var nonceToSign = await nonce(await identityOwner(identityDid));
    var paddedNonce = nonceToSign!.toRadixString(16).padLeft(64, '0');

    List<int> message = [];
    message.addAll(hexToBytes("0x19"));
    message.addAll(hexToBytes("0x00"));
    message.addAll(contractAddress.addressBytes);
    message.addAll(hexToBytes(paddedNonce));
    message.addAll(_didToAddress(identityDid).addressBytes);
    message.addAll("changeOwner".codeUnits);
    message.addAll(_didToAddress(newDid).addressBytes);

    var messageHash = keccak256(Uint8List.fromList(message));
    MsgSignature signature = sign(messageHash, privateKey);

    return signature;
  }

  Future<BigInt> estimateChangeOwner(String identityDid, String newDid) {
    var changeOwnerFunction = _erc1056contract.function('changeOwner');
    var tx = Transaction.callContract(
        contract: _erc1056contract,
        function: changeOwnerFunction,
        parameters: [_didToAddress(identityDid), _didToAddress(newDid)]);
    return web3Client.estimateGas(
        sender: _didToAddress(identityDid), data: tx.data, to: contractAddress);
  }

  Future<BigInt> estimateChangeOwnerSigned(
      String identityDid, String newDid, MsgSignature signature) {
    var changeOwnerSignedFunction =
        _erc1056contract.function('changeOwnerSigned');
    var tx = Transaction.callContract(
      contract: _erc1056contract,
      function: changeOwnerSignedFunction,
      parameters: [
        _didToAddress(identityDid),
        BigInt.from(signature.v),
        unsignedIntToBytes(signature.r),
        unsignedIntToBytes(signature.s),
        _didToAddress(newDid),
      ],
      // maxGas: 76853
    );
    return web3Client.estimateGas(
        sender: _didToAddress(identityDid), data: tx.data, to: contractAddress);
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

  Future<BigInt> estimateSetAttribute(
      String identityDid, String name, String value,
      [int validity = 86400]) {
    var setAttributeFunction = _erc1056contract.function('setAttribute');
    var valueList = Uint8List.fromList(utf8.encode(value));
    Transaction tx = Transaction.callContract(
        contract: _erc1056contract,
        function: setAttributeFunction,
        parameters: [
          _didToAddress(identityDid),
          _to32ByteUtf8(name),
          valueList,
          BigInt.from(validity)
        ]);

    return web3Client.estimateGas(
        sender: _didToAddress(identityDid), data: tx.data, to: contractAddress);
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

  Future<BigInt> estimateRevokeAttribute(
      String identityDid, String name, String value) {
    var revokeAttributeFunction = _erc1056contract.function('revokeAttribute');
    var nameList = _to32ByteUtf8(name);
    var valueList = Uint8List.fromList(utf8.encode(value));

    Transaction tx = Transaction.callContract(
        contract: _erc1056contract,
        function: revokeAttributeFunction,
        parameters: [_didToAddress(identityDid), nameList, valueList]);

    return web3Client.estimateGas(
        sender: _didToAddress(identityDid), data: tx.data, to: contractAddress);
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

  Future<BigInt> estimateAddDelegate(
      String identityDid, String delegateType, String delegateDid,
      [int validity = 86400]) {
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

    return web3Client.estimateGas(
        sender: _didToAddress(identityDid), data: tx.data, to: contractAddress);
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

  Future<BigInt> estimateRevokeDelegate(
      String identityDid, String delegateType, String delegateDid) {
    var revokeDelegateFunction = _erc1056contract.function('revokeDelegate');
    Transaction tx = Transaction.callContract(
        contract: _erc1056contract,
        function: revokeDelegateFunction,
        parameters: [
          _didToAddress(identityDid),
          _to32ByteUtf8(delegateType),
          _didToAddress(delegateDid)
        ]);

    return web3Client.estimateGas(
        sender: _didToAddress(identityDid), data: tx.data, to: contractAddress);
  }

  Future<bool>? validDelegate(
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

    return valid.first as bool;
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

  get namesToNumbers => _namesToNumbers;
}

EthereumAddress _didToAddress(String did) {
  var splitted = did.split(':');
  return EthereumAddress.fromHex(splitted.last);
}
