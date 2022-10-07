import 'dart:io';

import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/did.dart';
import 'package:dart_ssi/wallet.dart';
import 'package:test/test.dart';
import 'package:web3dart/crypto.dart';

void main() async {
  const String rpcUrl = 'http://127.0.0.1:7545';
  String contractAddress = '0xF7551cC988437d0D33A615cCE4716D8384Aa8AEB';
  var erc1056 = Erc1056(rpcUrl, contractAddress: contractAddress);
  var ganacheAccounts = WalletStore('ganacheNew');
  await ganacheAccounts.openBoxes('ganache');
  ganacheAccounts.initialize(
      mnemonic:
          'cave huge ripple fiber deny shove hello refuse push saddle siege notice');

  var ganacheDid5 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/4');
  var ganacheDid6 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/5');
  var ganacheDid7 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/6');
  var ganacheDid8 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/7');
  var ganacheDid9 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/8');
  var ganacheDid10 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/9');

  group('Delegate Operations', () {
    test('exception when type is too long', () async {
      expect(
          () async => await erc1056.addDelegate(
              await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/5'),
              ganacheDid6,
              'anAlittlebitToooooLongDelegateType',
              ganacheDid7),
          throwsException);
    });

    test('add one Delegate', () async {
      await erc1056.addDelegate(
          await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/5'),
          ganacheDid6,
          'Signer',
          ganacheDid7);

      expect(await erc1056.validDelegate(ganacheDid6, 'Signer', ganacheDid7),
          true);

      var eventData = await erc1056.collectEventData(ganacheDid6);
      List<String> signer = eventData['delegates']['Signer'];
      expect(signer.length, 1);
      expect(signer[0], ganacheDid7);
    });

    test('revoke added Delegate', () async {
      await erc1056.revokeDelegate(
          await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/5'),
          ganacheDid6,
          'Signer',
          ganacheDid7);
      expect(await erc1056.validDelegate(ganacheDid6, 'Signer', ganacheDid7),
          false);

      var eventData = await erc1056.collectEventData(ganacheDid6);
      List<String>? signer2 = eventData['delegates']['Signer'];
      expect(signer2, null);
    });

    test('add two delagates with same type', () async {
      await erc1056.addDelegate(
          await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/6'),
          ganacheDid7,
          'Signer',
          ganacheDid8);
      await erc1056.addDelegate(
          await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/6'),
          ganacheDid7,
          'Signer',
          ganacheDid5);

      expect(await erc1056.validDelegate(ganacheDid7, 'Signer', ganacheDid8),
          true);
      expect(await erc1056.validDelegate(ganacheDid7, 'Signer', ganacheDid5),
          true);
      var eventData = await erc1056.collectEventData(ganacheDid7);
      print(eventData);
      List<String> signer = eventData['delegates']['Signer'];
      expect(signer.length, 2);
      expect(signer.contains(ganacheDid8), true);
      expect(signer.contains(ganacheDid5), true);
    });

    test('revoke one out of two delegates', () async {
      await erc1056.revokeDelegate(
          await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/6'),
          ganacheDid7,
          'Signer',
          ganacheDid8);
      expect(await erc1056.validDelegate(ganacheDid7, 'Signer', ganacheDid8),
          false);
      expect(await erc1056.validDelegate(ganacheDid7, 'Signer', ganacheDid5),
          true);
      var eventData = await erc1056.collectEventData(ganacheDid7);
      List<String> signer = eventData['delegates']['Signer'];
      expect(signer.length, 1);
      expect(signer.contains(ganacheDid8), false);
      expect(signer.contains(ganacheDid5), true);
    });

    test('add delegate with other type', () async {
      await erc1056.addDelegate(
          await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/6'),
          ganacheDid7,
          'Other',
          ganacheDid8);
      expect(
          await erc1056.validDelegate(ganacheDid7, 'Other', ganacheDid8), true);
      expect(await erc1056.validDelegate(ganacheDid7, 'Signer', ganacheDid5),
          true);
      var eventData = await erc1056.collectEventData(ganacheDid7);
      List<String> signer = eventData['delegates']['Signer'];
      List<String> other = eventData['delegates']['Other'];
      expect(signer.length, 1);
      expect(signer.contains(ganacheDid8), false);
      expect(signer.contains(ganacheDid5), true);
      expect(other.length, 1);
      expect(other.contains(ganacheDid8), true);
      expect(other.contains(ganacheDid5), false);
    });
  });

  group('Owner Operations', () {
    test('change owner one time', () async {
      await erc1056.changeOwner(
          await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/6'),
          ganacheDid7,
          ganacheDid5);

      expect(
          () async => erc1056.changeOwner(
              await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/6'),
              ganacheDid7,
              ganacheDid5),
          throwsException);
      var identityOwner = await erc1056.identityOwner(ganacheDid7);
      expect(identityOwner, ganacheDid5);
      var eventData = await erc1056.collectEventData(ganacheDid7);
      List<String> owners = eventData['owners'];
      expect(owners.length, 1);
      expect(owners.contains(ganacheDid5), true);
    });

    test('change Owner a second time', () async {
      await erc1056.changeOwner(
          await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/4'),
          ganacheDid7,
          ganacheDid8);

      expect(
          () async => erc1056.changeOwner(
              await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/4'),
              ganacheDid7,
              ganacheDid8),
          throwsException);
      var identityOwner = await erc1056.identityOwner(ganacheDid7);
      expect(identityOwner, ganacheDid8);
      var eventData = await erc1056.collectEventData(ganacheDid7);
      List<String> owners = eventData['owners'];
      expect(owners.length, 2);
      expect(owners.contains(ganacheDid5), true);
      expect(owners.contains(ganacheDid8), true);
    });
  });

  group('attribute Operations', () {
    test('set one attribute', () async {
      await erc1056.setAttribute(
          await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/7'),
          ganacheDid8,
          'serviceEndpoint',
          'http://identity.service.de');

      var eventData = await erc1056.collectEventData(ganacheDid8);
      print(eventData);
      Map<String, List<String>> attributes = eventData['attributes'];
      expect(attributes.keys.length, 1);
      expect(attributes.containsKey('serviceEndpoint'), true);
      expect(
          attributes['serviceEndpoint']!.first, 'http://identity.service.de');
    });

    test('revoke one attribute', () async {
      await erc1056.revokeAttribute(
          await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/7'),
          ganacheDid8,
          'serviceEndpoint',
          'http://identity.service.de');

      var eventData = await erc1056.collectEventData(ganacheDid8);
      Map<String, List<String>> attributes = eventData['attributes'];
      expect(attributes.keys.length, 0);
      expect(attributes.containsKey('serviceEndpoint'), false);
    });

    test('attribute with very short validity', () async {
      await erc1056.setAttribute(
          await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/7'),
          ganacheDid8,
          'service',
          'http://identity.service.de',
          validity: 3);

      sleep(Duration(seconds: 4));
      var eventData = await erc1056.collectEventData(ganacheDid8);
      Map<String, List<String>> attributes = eventData['attributes'];
      expect(attributes.keys.length, 0);
      expect(attributes.containsKey('service'), false);
    });

    test('attribute with long value', () async {
      var value = 'longlonglong';
      value = value.padLeft(100, 'lo');
      value = value.padRight(200, 'KO');

      await erc1056.setAttribute(
          await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/7'),
          ganacheDid8,
          'LongService',
          value);

      var eventData = await erc1056.collectEventData(ganacheDid8);
      Map<String, List<String>> attributes = eventData['attributes'];
      expect(attributes.keys.length, 1);
      expect(attributes.containsKey('LongService'), true);
      expect(attributes['LongService']!.first, value);
    });

    test('two attributes with different names', () async {
      var value = 'longlonglong';
      value = value.padLeft(100, 'lo');
      value = value.padRight(200, 'KO');

      await erc1056.setAttribute(
          await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/7'),
          ganacheDid8,
          'serviceEndpoint',
          'http://identity.service.de');

      var eventData = await erc1056.collectEventData(ganacheDid8);
      Map<String, List<String>> attributes = eventData['attributes'];
      expect(attributes.keys.length, 2);
      expect(attributes.containsKey('LongService'), true);
      expect(attributes.containsKey('serviceEndpoint'), true);
      expect(attributes['LongService']!.first, value);
      expect(
          attributes['serviceEndpoint']!.first, 'http://identity.service.de');
    });

    test('two values for one attribute', () async {
      await erc1056.setAttribute(
          await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/7'),
          ganacheDid8,
          'serviceEndpoint',
          'http://hsmw.identity.service.de');

      var eventData = await erc1056.collectEventData(ganacheDid8);
      Map<String, List<String>> attributes = eventData['attributes'];
      expect(attributes.containsKey('serviceEndpoint'), true);
      expect(attributes['serviceEndpoint']!.length, 2);
      expect(
          attributes['serviceEndpoint']!
              .contains('http://hsmw.identity.service.de'),
          true);
      expect(
          attributes['serviceEndpoint']!.contains('http://identity.service.de'),
          true);
    });

    test('revoke one out of two attribute values', () async {
      await erc1056.revokeAttribute(
          await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/7'),
          ganacheDid8,
          'serviceEndpoint',
          'http://hsmw.identity.service.de');

      var eventData = await erc1056.collectEventData(ganacheDid8);
      Map<String, List<String>> attributes = eventData['attributes'];
      expect(attributes.containsKey('serviceEndpoint'), true);
      expect(attributes['serviceEndpoint']!.length, 1);
      expect(
          attributes['serviceEndpoint']!
              .contains('http://hsmw.identity.service.de'),
          false);
      expect(
          attributes['serviceEndpoint']!.contains('http://identity.service.de'),
          true);
    });
  });

  group('Revocation Contract', () {
    var rev = RevocationRegistry(rpcUrl);
    test('revoke something', () async {
      await rev
          .deploy(await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/6'));

      var isRevoked = await rev
          .isRevoked('did:ethr:0x3B974dC1107e45cDDf1174B810960A7212562Ae4');
      expect(isRevoked, false);

      await rev.revoke(
          await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/6'),
          'did:ethr:0x3B974dC1107e45cDDf1174B810960A7212562Ae4');

      isRevoked = await rev
          .isRevoked('did:ethr:0x3B974dC1107e45cDDf1174B810960A7212562Ae4');
      expect(isRevoked, true);

      var timestamp = await rev.revocationTimestamp(
          'did:ethr:0x3B974dC1107e45cDDf1174B810960A7212562Ae4');
      print(timestamp);
    });

    test('change Owner', () async {
      await rev.changeOwner(
          await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/6'),
          ganacheDid8);

      expect(
          () async => await rev.revoke('m/44\'/60\'/0\'/0/6',
              'did:ethr:0x6d32738382c6389eF0D79045a76411C42Fff3a5e'),
          throwsException);
    });
  });

  group('erc with network id', () {
    test('get owner did', () async {
      var ercWithId = Erc1056(rpcUrl,
          networkNameOrId: 'ganache', contractAddress: contractAddress);
      var did = await ercWithId.identityOwner(
          'did:ethr:ganache:0xC3d188C872e25c0370Ff3D2aA7268e2e13D11fe9');
      expect(did.startsWith('did:ethr:ganache'), true);
    });

    test('transact to private network', () async {
      var ercWithId = Erc1056(rpcUrl,
          networkNameOrId: 'ganache', contractAddress: contractAddress);
      ganacheDid10 = 'did:ethr:ganache:${ganacheDid10.split(':').last}';
      ganacheDid9 = 'did:ethr:ganache:${ganacheDid9.split(':').last}';
      expect(ercWithId.chainId, 1337);
      expect(await ercWithId.identityOwner(ganacheDid10), ganacheDid10);
      await ercWithId.changeOwner(
          await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/9'),
          ganacheDid10,
          ganacheDid9);
      expect(await ercWithId.identityOwner(ganacheDid10), ganacheDid9);
    });

    test('network id in did', () async {
      var ercWithId = Erc1056(rpcUrl,
          networkNameOrId: 'ganache', contractAddress: contractAddress);
      ganacheDid10 =
          'did:ethr:${bytesToHex(intToBytes(BigInt.from(1337)))}:${ganacheDid10.split(':').last}';
      ganacheDid9 = 'did:ethr:ganache:${ganacheDid9.split(':').last}';
      expect(await ercWithId.identityOwner(ganacheDid10), ganacheDid9);
    });

    test('Exception did not in network', () {
      var ercWithId =
          Erc1056(rpcUrl, networkNameOrId: 3, contractAddress: contractAddress);
      ganacheDid9 = 'did:ethr:ganache:${ganacheDid9.split(':').last}';
      expect(ercWithId.networkName, 'ropsten');
      expect(() async => await ercWithId.identityOwner(ganacheDid9),
          throwsException);
    });
  });
}
