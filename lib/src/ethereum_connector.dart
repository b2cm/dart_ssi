import 'dart:convert';
import 'dart:typed_data';

import 'package:ethereum_util/ethereum_util.dart';
import 'package:http/http.dart';
import 'package:web3dart/web3dart.dart';
import 'package:web_socket_channel/io.dart';

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

  DeployedContract erc1056contract;
  Web3Client web3Client;
  EthereumAddress contractAddress;

  Erc1056(String rpcUrl,
      {String websocketUrl,
      String contractName: 'EthereumDIDRegistry',
      String contractAddress: '0xdca7ef03e98e0dc2b855be647c39abe984fcf21b'}) {
    this.contractAddress = EthereumAddress.fromHex(contractAddress);

    erc1056contract = DeployedContract(
        ContractAbi.fromJson(abi, contractName), this.contractAddress);

    if (websocketUrl == null)
      web3Client = Web3Client(rpcUrl, Client());
    else
      web3Client = Web3Client(rpcUrl, Client(), socketConnector: () {
        return IOWebSocketChannel.connect(websocketUrl).cast<String>();
      });
  }

  /// Requst the current owner (Ethereum Address) for identity [did].
  Future<String> identityOwner(String did) async {
    var identityOwnerFunction = erc1056contract.function('identityOwner');
    var owner = await web3Client.call(
        contract: erc1056contract,
        function: identityOwnerFunction,
        params: [_didToAddress(did)]);
    print(owner);
    var ownerAddress = owner.first as EthereumAddress;
    return ownerAddress.hexEip55;
  }

  Future<void> changeOwner(
      String privateKeyFrom, String identityDid, String newDid) async {
    var changeOwnerFunction = erc1056contract.function('changeOwner');

    await web3Client.sendTransaction(
        EthPrivateKey.fromHex(privateKeyFrom),
        Transaction.callContract(
            contract: erc1056contract,
            function: changeOwnerFunction,
            parameters: [_didToAddress(identityDid), _didToAddress(newDid)]));
  }

  Future<void> setAttribute(
      String privateKeyFrom, String identityDid, String name, String value,
      {int validity: 86400}) async {
    if (validity <= 0) throw Exception('negative validity');
    var setAttributeFunction = erc1056contract.function('setAttribute');
    var valueList = Uint8List.fromList(ascii.encode(value));
    Transaction tx = Transaction.callContract(
        contract: erc1056contract,
        function: setAttributeFunction,
        parameters: [
          _didToAddress(identityDid),
          _to32ByteAscii(name),
          valueList,
          BigInt.from(validity)
        ]);

    await web3Client.sendTransaction(EthPrivateKey.fromHex(privateKeyFrom), tx);
  }

  Future<void> revokeAttribute(String privateKeyFrom, String identityDid,
      String name, String value) async {
    var revokeAttributeFunction = erc1056contract.function('revokeAttribute');
    var nameList = _to32ByteAscii(name);
    var valueList = Uint8List.fromList(ascii.encode(value));

    Transaction tx = Transaction.callContract(
        contract: erc1056contract,
        function: revokeAttributeFunction,
        parameters: [_didToAddress(identityDid), nameList, valueList]);

    await web3Client.sendTransaction(EthPrivateKey.fromHex(privateKeyFrom), tx);
  }

  Future<void> addDelegate(String privateKeyFrom, String identityDid,
      String delegateType, String delegateDid,
      {int validity: 86400}) async {
    if (validity <= 0) throw Exception('negative validity');
    var addDelegateFunction = erc1056contract.function('addDelegate');
    Transaction tx = Transaction.callContract(
        contract: erc1056contract,
        function: addDelegateFunction,
        parameters: [
          _didToAddress(identityDid),
          _to32ByteAscii(delegateType),
          _didToAddress(delegateDid),
          BigInt.from(validity)
        ]);

    await web3Client.sendTransaction(EthPrivateKey.fromHex(privateKeyFrom), tx);
  }

  Future<void> revokeDelegate(String privateKeyFrom, String identityDid,
      String delegateType, String delegateDid) async {
    var revokeDelegateFunction = erc1056contract.function('revokeDelegate');
    Transaction tx = Transaction.callContract(
        contract: erc1056contract,
        function: revokeDelegateFunction,
        parameters: [
          _didToAddress(identityDid),
          _to32ByteAscii(delegateType),
          _didToAddress(delegateDid)
        ]);

    await web3Client.sendTransaction(EthPrivateKey.fromHex(privateKeyFrom), tx);
  }

  Future<bool> validDelegate(
      String identityDid, String delegateType, String delegateDid) async {
    var validDelegateFunction = erc1056contract.function('validDelegate');
    var valid = await web3Client.call(
        contract: erc1056contract,
        function: validDelegateFunction,
        params: [
          _didToAddress(identityDid),
          _to32ByteAscii(delegateType),
          _didToAddress(delegateDid)
        ]);

    return valid.first as bool;
  }

  Future<BigInt> changed(String identityDid) async {
    var changedFunction = erc1056contract.function('changed');
    var changedBlock = await web3Client.call(
        contract: erc1056contract,
        function: changedFunction,
        params: [_didToAddress(identityDid)]);
    return changedBlock.first as BigInt;
  }

  Future<BigInt> nonce(String identityDid) async {
    var nonceFunction = erc1056contract.function('nonce');
    var nonceValue = await web3Client.call(
        contract: erc1056contract,
        function: nonceFunction,
        params: [_didToAddress(identityDid)]);

    return nonceValue.first as BigInt;
  }

  ///Collects all data from contract log for [identityDid].
  ///
  /// It returns a map containing the keys owners, attributes and delegates. Behind owners-key
  /// is a List<String> with the hex-representation of all the ethereum addresses that
  /// controlled this identity in the past. attributes and delegates gives a Map<String, List<String>>
  /// mapping the delegate-type or attribute-name to their values.
  Future<Map<String, dynamic>> collectEventData(String identityDid) async {
    var didOwnerChangedEvent = erc1056contract.event('DIDOwnerChanged');
    var didDelegateChangedEvent = erc1056contract.event('DIDDelegateChanged');
    var didAttributeChangedEvent = erc1056contract.event('DIDAttributeChanged');
    var owners = List<String>();
    var delegates = Map<String, List<String>>();
    var attributes = Map<String, List<String>>();
    var revokedAttributes = List<String>();
    int secNow = (DateTime.now().millisecondsSinceEpoch ~/ 1000);

    var lastChange = await changed(identityDid);

    while (lastChange != BigInt.zero) {
      var logs = await web3Client.getLogs(FilterOptions(
          fromBlock: BlockNum.exact(lastChange.toInt()),
          toBlock: BlockNum.exact(lastChange.toInt()),
          topics: [
            null,
            ['0x${_didToAddress(identityDid).hexNo0x.padLeft(64, '0')}']
          ]));
      var listOfPreviousChanges = List<BigInt>();

      await Future.forEach(logs, (event) async {
        if (event.topics.first == bufferToHex(didOwnerChangedEvent.signature)) {
          var decodedEvent =
              didOwnerChangedEvent.decodeResults(event.topics, event.data);
          var owner = decodedEvent[1] as EthereumAddress;
          var previousChange = decodedEvent[2] as BigInt;

          listOfPreviousChanges.add(previousChange);
          owners.add(_addressToDid(owner));
        } else if (event.topics.first ==
            bufferToHex(didAttributeChangedEvent.signature)) {
          var decodedEvent =
              didAttributeChangedEvent.decodeResults(event.topics, event.data);
          var name = decodedEvent[1] as Uint8List;
          var value = decodedEvent[2] as Uint8List;
          var validTo = decodedEvent[3] as BigInt;
          var previousChange = decodedEvent[4] as BigInt;
          var nameStr = _bytes32ToString(name);
          var valueStr = ascii.decode(value);

          listOfPreviousChanges.add(previousChange);

          if (validTo < BigInt.from(secNow)) {
            revokedAttributes.add('$nameStr-$valueStr');
          } else {
            if (!revokedAttributes.contains('$nameStr-$valueStr')) {
              if (attributes.containsKey(nameStr) &&
                  (!attributes[nameStr].contains(valueStr))) {
                attributes[nameStr].add(valueStr);
              } else {
                var tmp = List<String>();
                tmp.add(valueStr);
                attributes[nameStr] = tmp;
              }
            }
          }
        } else if (event.topics.first ==
            bufferToHex(didDelegateChangedEvent.signature)) {
          var decodedEvent =
              didDelegateChangedEvent.decodeResults(event.topics, event.data);
          var delegateType = decodedEvent[1] as Uint8List;
          var delegate = decodedEvent[2] as EthereumAddress;
          var previousChange = decodedEvent[4] as BigInt;
          var delegateTypeString = _bytes32ToString(delegateType);

          listOfPreviousChanges.add(previousChange);

          var validDelegate = await this.validDelegate(
              identityDid, delegateTypeString, _addressToDid(delegate));
          if (validDelegate) {
            if (delegates.containsKey(delegateTypeString) &&
                (!delegates[delegateTypeString]
                    .contains(_addressToDid(delegate)))) {
              delegates[delegateTypeString].add(_addressToDid(delegate));
            } else {
              var tmpList = List<String>();
              tmpList.add(_addressToDid(delegate));
              delegates[delegateTypeString] = tmpList;
            }
          }
        } else {
          throw Exception('Unknown Event-Signature ${event.topics.first}');
        }
      });

      listOfPreviousChanges.sort();
      BigInt lastChangeNew = listOfPreviousChanges.last;
      for (int i = listOfPreviousChanges.length - 1; i >= 0; i--) {
        if (lastChangeNew != lastChange &&
            (!(listOfPreviousChanges[i] < lastChangeNew))) {
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

  Uint8List _to32ByteAscii(String name) {
    var nameAscii = ascii.encode(name);
    if (nameAscii.length > 32) throw Exception('name is too long');
    var nameList = Uint8List(32);
    for (int i = 0; i < nameAscii.length; i++) {
      nameList[i] = nameAscii[i];
    }
    return nameList;
  }

  String _bytes32ToString(Uint8List value) {
    List<int> nameUnpadded = List();
    for (int i = 0; i < value.length; i++) {
      if (value[i] != 0) nameUnpadded.add(value[i]);
    }
    return ascii.decode(nameUnpadded);
  }

  EthereumAddress _didToAddress(String did) {
    var splitted = did.split(':');
    return EthereumAddress.fromHex(splitted[2]);
  }

  String _addressToDid(EthereumAddress address) {
    return 'did:ethr:${address.hexEip55}';
  }
}
