import 'package:flutter_ssi_wallet/flutter_ssi_wallet.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
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
}
