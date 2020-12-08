import 'dart:convert';
import 'dart:io';

import 'package:flutter_ssi_wallet/flutter_ssi_wallet.dart';
import 'package:flutter_test/flutter_test.dart';

void main() async {
  const String rpcUrl = 'http://127.0.0.1:7545';
  var erc1056 = Erc1056(rpcUrl,
      contractAddress: '0x0eE301c92471234038E320153A7F650ab9a72e28');
  var ganacheAccounts = new WalletStore('ganache');
  await ganacheAccounts.openBoxes('ganache');
  // ganacheAccounts.initialize(
  //     'situate recall vapor van layer stage nerve wink gap vague muffin vacuum');

  var ganacheDid5 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/4');
  var ganacheDid6 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/5');
  var ganacheDid7 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/6');
  var ganacheDid8 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/7');
  var ganacheDid9 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/8');
  var ganacheDid10 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/9');
  ganacheAccounts.storeCredential('', '', 'm/44\'/60\'/0\'/0/8');
  test('test get issuer did from Credential', () {
    String cred1 = '{"issuer": "did:ethr:123456"}';
    String cred2 = '{"issuer": {"id" : "did:ethr:123456", "name" : "HSMW"}}';
    String cred3 = '{"id" : "did:123456"}';
    String cred4 = '{"issuer": {"name" : "HSMW"}}';

    expect(getIssuerDidFromCredential(cred1), 'did:ethr:123456');
    expect(getIssuerDidFromCredential(cred2), 'did:ethr:123456');
    expect(getIssuerDidFromCredential(cred3), null);
    expect(getIssuerDidFromCredential(cred4), null);
  });

  test('test build JWS Header', () {
    var critical = new Map<String, dynamic>();
    critical.putIfAbsent('b64', () => false);
    var header = buildJwsHeader(alg: 'ES256K-R', extra: critical);
    expect(
        header, 'eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19');
  });

  test('build Plaintext Credential', () {
    var plaintext = {'name': 'Max', 'age': 20};

    var cred = buildPlaintextCredential(plaintext);
    var credObject = jsonDecode(cred);
    print(cred);

    expect(credObject['name']['value'], 'Max');
  });

  test('credential revocation', () async {
    var plaintext = {'name': 'Max', 'age': 20};
    var rev = RevocationRegistry(rpcUrl);
    var revAddress =
        await rev.deploy(ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/8'));
    var cred = buildPlaintextCredential(plaintext);
    var w3cCred = buildW3cCredentialwithHashes(cred, ganacheDid6, ganacheDid9,
        revocationRegistryAddress: revAddress);
    var signed = signCredential(ganacheAccounts, w3cCred);
    await new File('withRevocationRegistry.json').writeAsString(signed);
    var verified = await verifyCredential(signed, erc1056, rpcUrl);
    expect(verified, true);

    await rev.revoke(
        ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/8'), ganacheDid6);

    expect(() async => await verifyCredential(signed, erc1056, rpcUrl),
        throwsException);
  });
}
