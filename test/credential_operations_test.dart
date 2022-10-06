import 'dart:convert';
import 'dart:io';

import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/did.dart';
import 'package:dart_ssi/wallet.dart';
import 'package:http/http.dart';
import 'package:json_schema2/json_schema2.dart';
import 'package:test/test.dart';
import 'package:uuid/uuid.dart';
import 'package:web3dart/web3dart.dart';

void main() async {
  const String rpcUrl = 'http://127.0.0.1:7545';
  //const String rpcUrl = 'https://credentials.hs-mittweida.de:33005';

  var erc1056 = Erc1056(rpcUrl,
      contractAddress: '0x0eE301c92471234038E320153A7F650ab9a72e28');
  var revocationRegistry = RevocationRegistry(rpcUrl);
  var ganacheAccounts = WalletStore('ganache');
  await ganacheAccounts.openBoxes('ganache');
  await ganacheAccounts.initialize(
      mnemonic:
          'situate recall vapor van layer stage nerve wink gap vague muffin vacuum');

  var ganacheDid6 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/5');
  var ganacheDid9 = await ganacheAccounts.getDid('m/44\'/60\'/0\'/0/8');

  ganacheAccounts.storeCredential('', '', 'm/44\'/60\'/0\'/0/8');
  test('test get issuer did from Credential', () {
    String cred1 = '{"issuer": "did:ethr:123456"}';
    String cred2 = '{"issuer": {"id" : "did:ethr:123456", "name" : "HSMW"}}';
    String cred3 = '{"id" : "did:123456"}';
    String cred4 = '{"issuer": {"name" : "HSMW"}}';

    expect(getIssuerDidFromCredential(cred1), 'did:ethr:123456');
    expect(getIssuerDidFromCredential(cred2), 'did:ethr:123456');
    expect(getIssuerDidFromCredential(cred3), '');
    expect(getIssuerDidFromCredential(cred4), '');
  });

  test('test build JWS Header', () {
    var critical = <String, dynamic>{};
    critical.putIfAbsent('b64', () => false);
    var header = buildJwsHeader(alg: 'ES256K-R', extra: critical);
    expect(
        header, 'eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19');
  });

  group('build Plaintext Credential', () {
    var hashedAttributeSchema = {
      "type": "object",
      "required": ['salt', 'value'],
      "properties": {
        "value": {
          "type": ["number", "string", "boolean"]
        },
        "salt": {"type": "string", 'minLenght': 36, 'maxLenght': 36}
      },
      "additionalProperties": false
    };

    var jScheme = JsonSchema.createSchema(hashedAttributeSchema);
    test('normal key-value-pairs (given as Map)', () {
      var plaintext = {'name': 'Max'};

      var cred = buildPlaintextCredential(plaintext, 'did:ethr:0x123');
      var credObject = jsonDecode(cred);
      var schema = {
        'type': 'object',
        'required': ['id', 'name'],
        'properties': {
          'name': hashedAttributeSchema,
          'id': {'type': 'string'}
        }
      };
      var jSchema = JsonSchema.createSchema(schema);
      expect(credObject['name']['value'], 'Max');
      expect(jSchema.validate(credObject), true);
    });

    test('normal key-value-pairs (given as String)', () {
      var plaintext = '{"name": "Max"}';

      var cred = buildPlaintextCredential(plaintext, 'did:ethr:0x123');
      var credObject = jsonDecode(cred);
      var schema = {
        'type': 'object',
        'required': ['id', 'name'],
        'properties': {
          'name': hashedAttributeSchema,
          'id': {'type': 'string'}
        }
      };
      var jSchema = JsonSchema.createSchema(schema);
      expect(credObject['name']['value'], 'Max');
      expect(jSchema.validate(credObject), true);
    });

    test('array with string, num, boolean (given as map)', () {
      var plaintext = {
        'hobbies': ['lesen', true, 20, 30.8]
      };

      var cred = buildPlaintextCredential(plaintext, 'did:ethr:0x123');
      var credObject = jsonDecode(cred);

      expect(plaintext['hobbies']!.length, credObject['hobbies'].length);

      for (int i = 0; i < plaintext['hobbies']!.length; i++) {
        expect(plaintext['hobbies']![i], credObject['hobbies'][i]['value']);
        expect(jScheme.validate(credObject['hobbies'][i]), true);
      }
    });

    test('array with string, num, boolean (given as String)', () {
      var plaintext = '{"hobbies": ["lesen", true, 20, 30.8]}';

      var cred = buildPlaintextCredential(plaintext, 'did:ethr:0x123');
      var credObject = jsonDecode(cred);

      expect(credObject['hobbies'].length, 4);

      for (int i = 0; i < credObject['hobbies'].length; i++) {
        expect(jScheme.validate(credObject['hobbies'][i]), true);
      }
    });

    test('array with objects (given as map)', () {
      var plaintext = {
        'hobbies': [
          {'name': 'schwimmen', 'duration': 3},
          {'name': 'reiten', 'duration': 7}
        ]
      };

      var cred = buildPlaintextCredential(plaintext, 'did:ethr:0x123');
      var credObject = jsonDecode(cred);

      expect(credObject['hobbies'].length, plaintext['hobbies']!.length);
      for (int i = 1; i < credObject['hobbies'].length; i++) {
        expect(jScheme.validate(credObject['hobbies'][i]['name']), true);
        expect(jScheme.validate(credObject['hobbies'][i]['duration']), true);
      }
    });

    test('array with objects (given as string)', () {
      var plaintext =
          '{"hobbies": [{"name": "schwimmen", "duration": 3},{"name": "reiten", "duration": 7}]}';

      var cred = buildPlaintextCredential(plaintext, 'did:ethr:0x123');
      var credObject = jsonDecode(cred);

      expect(credObject['hobbies'].length, 2);
      for (int i = 1; i < credObject['hobbies'].length; i++) {
        expect(jScheme.validate(credObject['hobbies'][i]['name']), true);
        expect(jScheme.validate(credObject['hobbies'][i]['duration']), true);
      }
    });

    test('array with array', () {
      var plaintext = {
        'grades': [
          [1, 2],
          [5, 4]
        ]
      };

      expect(() => buildPlaintextCredential(plaintext, 'did:ethr:0x123'),
          throwsException);
    });

    test('objects (given as Map)', () {
      var plaintext = {
        'mother': {'name': 'Mustermann', 'surname': 'Erika'}
      };

      var cred = buildPlaintextCredential(plaintext, 'did:ethr:0x123');
      var credObject = jsonDecode(cred);

      expect(jScheme.validate(credObject['mother']['name']), true);
      expect(jScheme.validate(credObject['mother']['surname']), true);
      expect(credObject['mother']['name']['value'], 'Mustermann');
      expect(credObject['mother']['surname']['value'], 'Erika');
      expect(credObject['mother'].length, plaintext['mother']!.length);
    });

    test('objects (given as string)', () {
      var plaintext = '{"mother": {"name": "Mustermann", "surname": "Erika"}}';

      var cred = buildPlaintextCredential(plaintext, 'did:ethr:0x123');
      var credObject = jsonDecode(cred);

      expect(jScheme.validate(credObject['mother']['name']), true);
      expect(jScheme.validate(credObject['mother']['surname']), true);
      expect(credObject['mother']['name']['value'], 'Mustermann');
      expect(credObject['mother']['surname']['value'], 'Erika');
      expect(credObject['mother'].length, 2);
    });

    test('ignore @context (as List)', () {
      var plaintext = {
        '@context': ['https://hs-mittweida.de']
      };
      var cred = buildPlaintextCredential(plaintext, 'did:ethr:0x123');
      var credObject = jsonDecode(cred);
      expect(credObject['@context'].length, 1);
      expect(credObject['hashAlg'], 'keccak-256');
      expect(credObject['@context'][0], 'https://hs-mittweida.de');
      expect(credObject.keys.length, 3);
      expect(jScheme.validate(credObject['@context']), false);
    });

    test('ignore @context (as String)', () {
      var plaintext = {'@context': 'https://hs-mittweida.de'};
      var cred = buildPlaintextCredential(plaintext, 'did:ethr:0x123');
      var credObject = jsonDecode(cred);
      expect(credObject['@context'], 'https://hs-mittweida.de');
      expect(jScheme.validate(credObject['@context']), false);
    });

    test('maleformed json-String', () {
      var plaintext = '{"key" : value';
      expect(() => buildPlaintextCredential(plaintext, 'did:ethr:0x123'),
          throwsException);
    });

    test('not a Map or String', () {
      var plaintext = ['value1', 'value2'];
      expect(() => buildPlaintextCredential(plaintext, 'did:ethr:0x123'),
          throwsException);
    });

    test('long value', () {
      var value = 'value';
      value = value.padLeft(500, 'abcd');
      var plaintext = {'key': value};
      var cred = buildPlaintextCredential(plaintext, 'did:ethr:0x123');
      var credObject = jsonDecode(cred);

      expect(credObject['key']['value'], value);
      expect(jScheme.validate(credObject['key']), true);
    });

    group('collect types', () {
      test('type as  new String', () {
        var cred = {'type': 'NameAgeCredential', 'name': 'Max', 'age': 12};
        Map<String, dynamic> plaintext =
            jsonDecode(buildPlaintextCredential(cred, 'did:ethr:0x135768'));
        List<dynamic> types = plaintext['type'];
        expect(types.length, 2);
        expect(types.contains('NameAgeCredential'), true);
        expect(types.contains('HashedPlaintextCredential2021'), true);
      });

      test('do not add HashedPlaintextCredential (String)', () {
        var cred = {
          'type': 'HashedPlaintextCredential2021',
          'name': 'Max',
          'age': 12
        };
        Map<String, dynamic> plaintext =
            jsonDecode(buildPlaintextCredential(cred, 'did:ethr:0x135768'));
        List<dynamic> types = plaintext['type'];
        expect(types.length, 1);
        expect(types.contains('HashedPlaintextCredential2021'), true);
      });

      test('types as  List', () {
        var cred = {
          'type': ['NameAgeCredential', 'NameCredential'],
          'name': 'Max',
          'age': 12
        };
        Map<String, dynamic> plaintext =
            jsonDecode(buildPlaintextCredential(cred, 'did:ethr:0x135768'));
        List<dynamic> types = plaintext['type'];
        expect(types.length, 3);
        expect(types.contains('NameAgeCredential'), true);
        expect(types.contains('NameCredential'), true);
        expect(types.contains('HashedPlaintextCredential2021'), true);
      });

      test('do not add HashedPlaintextCredential2021 (List)', () {
        var cred = {
          'type': [
            'NameAgeCredential',
            'NameCredential',
            'HashedPlaintextCredential2021'
          ],
          'name': 'Max',
          'age': 12
        };
        Map<String, dynamic> plaintext =
            jsonDecode(buildPlaintextCredential(cred, 'did:ethr:0x135768'));
        List<dynamic> types = plaintext['type'];
        expect(types.length, 3);
        expect(types.contains('NameAgeCredential'), true);
        expect(types.contains('NameCredential'), true);
        expect(types.contains('HashedPlaintextCredential2021'), true);
      });

      test('ignore nested types', () {
        var cred = {
          'type': ['NameAgeCredential', 'NameCredential'],
          'name': 'Max',
          'age': 12,
          'address': {'type': 'PostalAddress'}
        };
        Map<String, dynamic> plaintext =
            jsonDecode(buildPlaintextCredential(cred, 'did:ethr:0x135768'));
        List<dynamic> types = plaintext['type'];
        expect(types.length, 3);
        expect(types.contains('NameAgeCredential'), true);
        expect(types.contains('NameCredential'), true);
        expect(types.contains('HashedPlaintextCredential2021'), true);
        expect(plaintext['address']['type'], 'PostalAddress');
      });
    });
  });

  group('build W3C Credential with Hashes', () {
    var credSchema = {
      'type': 'object',
      'required': [
        '@context',
        'type',
        'credentialSubject',
        'issuer',
        'issuanceDate'
      ],
      'properties': {
        '@context': {
          'type': 'array',
          'items': {'type': 'string'},
          'minItems': 1,
          'uniqueItems': true
        },
        'type': {
          'type': 'array',
          'items': {'type': 'string'},
          'minItems': 1,
          'uniqueItems': true
        },
        'credentialSubject': {
          'type': 'object',
          'required': ['id'],
          'properties': {
            'id': {'type': 'string'},
            'type': {'type': 'string'},
            r'^.*$': {
              'type': ['string', 'array', 'object'],
            }
          },
          'issuer': {
            'type': ['string', 'object']
          },
          'issuanceDate': {'type': 'string'}
        },
        'additionalProperties': false
      }
    };

    var w3cCredSchema = JsonSchema.createSchema(credSchema);

    test('plaintext has normal key-value Object', () {
      var plaintext =
          '{"id": "did:ethr:0x1234","givenName":{"value":"Max","salt":"d51e87c4-6ab5-4cf0-b932-28f6962c384e"}}';
      var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
      var w3cObj = jsonDecode(w3c);

      expect(w3cCredSchema.validate(w3cObj), true);
      expect(w3cObj['credentialSubject']['givenName'],
          '0x42892f9a183f8e47ea6b56cb4a0047e96effba9927cd44c3ba2097ff4fad70b4');
    });

    test('plaintext has array', () {
      var plaintext = {
        "id": "did:ethr:0x12234",
        "courseOfStudies": [
          {
            "value": "Cybercrime/Cybersecurity",
            "salt": "5ccf63ee-78fa-437c-a302-6c3cd3549fec"
          },
          {
            "value": "Angewandte Informatik - IT-Sicherheit",
            "salt": "6040c2d6-3931-4851-960a-93972e53483d"
          }
        ]
      };

      var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
      var w3cObj = jsonDecode(w3c);

      expect(w3cCredSchema.validate(w3cObj), true);
      expect(w3cObj['credentialSubject']['courseOfStudies'].length, 2);
      expect(w3cObj['credentialSubject']['courseOfStudies'][0],
          '0x12915d6160b6c9359dc4a0382388012786b8e3cd2351ccfff485683ae0e2fa10');
      expect(w3cObj['credentialSubject']['courseOfStudies'][1],
          '0x6994dbf74e9418b87a8c2a5645239a340d6203b8d3792a28fdfaab3d905c27b7');
    });

    test('plaintext has object', () {
      var plaintext = {
        "id": "did:ethr:0x12234",
        "address": {
          "addressLocality": {
            "value": "Mittweida",
            "salt": "e0d91fc0-ffda-4784-b0bc-077bed54c5c7"
          },
          "postalCode": {
            "value": "09648",
            "salt": "6977dcb5-f0e7-4158-a8f8-08cdac88d5b4"
          }
        }
      };

      var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
      var w3cObj = jsonDecode(w3c);

      expect(w3cCredSchema.validate(w3cObj), true);
      expect(w3cObj['credentialSubject']['address']['postalCode'],
          '0x68c9b55a1fb3cc542942d2c27978ab34433e171ecd91bf91ba882dfd4e0b08f6');
      expect(w3cObj['credentialSubject']['address']['addressLocality'],
          '0xd555aeaa1f0bc42adc3210240c9eeb2e35640cec110aeddd8f77d1762ba6bce1');
    });

    test('plaintext has object in a object', () {
      var value = {
        'friend': {
          'address': {
            'postcode': '09648',
            'streetAddress': {'street': 'Main Street', 'number': 78}
          }
        }
      };

      var plaintext = buildPlaintextCredential(value, 'did:ethr:0x123456');
      var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
      var w3cObj = jsonDecode(w3c);
      expect(w3cCredSchema.validate(w3cObj), true);
    });

    test('ignore type', () {
      var plaintext = {
        "id": "did:ethr:0x12234",
        "type": "Person",
        "givenName": {
          "value": "Max",
          "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
        }
      };
      var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
      var w3cObj = jsonDecode(w3c);

      expect(w3cCredSchema.validate(w3cObj), true);
      expect(w3cObj['credentialSubject']['givenName'],
          '0x42892f9a183f8e47ea6b56cb4a0047e96effba9927cd44c3ba2097ff4fad70b4');
      expect(w3cObj['credentialSubject']['type'], 'Person');
    });

    test('ignore @type', () {
      var plaintext = {
        "id": "did:ethr:0x12234",
        "@type": "Person",
        "givenName": {
          "value": "Max",
          "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
        }
      };
      var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
      var w3cObj = jsonDecode(w3c);

      expect(w3cCredSchema.validate(w3cObj), true);
      expect(w3cObj['credentialSubject']['givenName'],
          '0x42892f9a183f8e47ea6b56cb4a0047e96effba9927cd44c3ba2097ff4fad70b4');
      expect(w3cObj['credentialSubject']['@type'], 'Person');
    });

    group('parameter type', () {
      test('value VerifiableCredential should not be added (given as String)',
          () {
        var plaintext = {
          "id": "did:ethr:0x12234",
          "givenName": {
            "value": "Max",
            "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
          }
        };
        var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678',
            type: 'VerifiableCredential');
        var w3cObj = jsonDecode(w3c);
        expect(w3cCredSchema.validate(w3cObj), true);
        expect(w3cObj['type'].length, 1);
      });

      test('value VerifiableCredential should not be added (given as List)',
          () {
        var plaintext = {
          "id": "did:ethr:0x12234",
          "givenName": {
            "value": "Max",
            "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
          }
        };
        var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678',
            type: ['VerifiableCredential']);
        var w3cObj = jsonDecode(w3c);
        expect(w3cCredSchema.validate(w3cObj), true);
        expect(w3cObj['type'].length, 1);
      });

      test('add one value', () {
        var plaintext = {
          "id": "did:ethr:0x12234",
          "givenName": {
            "value": "Max",
            "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
          }
        };
        var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678',
            type: 'ImmaCredential');
        var w3cObj = jsonDecode(w3c);
        expect(w3cCredSchema.validate(w3cObj), true);
        expect(w3cObj['type'].length, 2);
        expect(w3cObj['type'].contains('VerifiableCredential'), true);
        expect(w3cObj['type'].contains('ImmaCredential'), true);
      });

      test('add a List of values', () {
        var plaintext = {
          "id": "did:ethr:0x12234",
          "givenName": {
            "value": "Max",
            "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
          }
        };
        var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678',
            type: ['ImmaCredential', 'Immatrikulation']);
        var w3cObj = jsonDecode(w3c);
        expect(w3cCredSchema.validate(w3cObj), true);
        expect(w3cObj['type'].length, 3);
        expect(w3cObj['type'].contains('VerifiableCredential'), true);
        expect(w3cObj['type'].contains('ImmaCredential'), true);
        expect(w3cObj['type'].contains('Immatrikulation'), true);
      });

      test('add a List of values without adding VerifiableCredential', () {
        var plaintext = {
          "id": "did:ethr:0x12234",
          "givenName": {
            "value": "Max",
            "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
          }
        };
        var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678',
            type: [
              'ImmaCredential',
              'Immatrikulation',
              'VerifiableCredential'
            ]);
        var w3cObj = jsonDecode(w3c);
        expect(w3cCredSchema.validate(w3cObj), true);
        expect(w3cObj['type'].length, 3);
        expect(w3cObj['type'].contains('VerifiableCredential'), true);
        expect(w3cObj['type'].contains('ImmaCredential'), true);
        expect(w3cObj['type'].contains('Immatrikulation'), true);
      });

      test('wrong datatypes', () {
        var plaintext = {
          "givenName": {
            "value": "Max",
            "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
          }
        };

        expect(
            () => buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678',
                type: 20),
            throwsException);
        expect(
            () => buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678',
                type: true),
            throwsException);
        expect(
            () => buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678',
                type: {'key': 'value'}),
            throwsException);
      });
    });

    group('parameter context / handling of @context in credential', () {
      test(
          'do not add https://www.w3.org/2018/credentials/v1 (given as string)',
          () {
        var plaintext = {
          "id": "did:ethr:0x12234",
          "givenName": {
            "value": "Max",
            "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
          }
        };

        var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678',
            context: 'https://www.w3.org/2018/credentials/v1');
        var w3cObj = jsonDecode(w3c);
        expect(w3cCredSchema.validate(w3cObj), true);
        expect(w3cObj['@context'].length, 1);
        expect(w3cObj['@context'][0], 'https://www.w3.org/2018/credentials/v1');
      });

      test('do not add https://www.w3.org/2018/credentials/v1 (given as list)',
          () {
        var plaintext = {
          "id": "did:ethr:0x12234",
          "givenName": {
            "value": "Max",
            "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
          }
        };

        var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678',
            context: ['https://www.w3.org/2018/credentials/v1']);
        var w3cObj = jsonDecode(w3c);
        expect(w3cCredSchema.validate(w3cObj), true);
        expect(w3cObj['@context'].length, 1);
        expect(w3cObj['@context'][0], 'https://www.w3.org/2018/credentials/v1');
      });

      test('add one value as String', () {
        var plaintext = {
          "id": "did:ethr:0x12234",
          "givenName": {
            "value": "Max",
            "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
          }
        };

        var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678',
            context: 'https://hs-mittweida.de/creds');
        var w3cObj = jsonDecode(w3c);
        expect(w3cCredSchema.validate(w3cObj), true);
        expect(w3cObj['@context'].length, 2);
        expect(w3cObj['@context'][0], 'https://www.w3.org/2018/credentials/v1');
        expect(
            w3cObj['@context'].contains('https://hs-mittweida.de/creds'), true);
      });

      test('add one value as List', () {
        var plaintext = {
          "id": "did:ethr:0x12234",
          "givenName": {
            "value": "Max",
            "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
          }
        };

        var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678',
            context: ['https://hs-mittweida.de/creds']);
        var w3cObj = jsonDecode(w3c);
        expect(w3cCredSchema.validate(w3cObj), true);
        expect(w3cObj['@context'].length, 2);
        expect(w3cObj['@context'][0], 'https://www.w3.org/2018/credentials/v1');
        expect(
            w3cObj['@context'].contains('https://hs-mittweida.de/creds'), true);
      });

      test('add a List of values', () {
        var plaintext = {
          "id": "did:ethr:0x12234",
          "givenName": {
            "value": "Max",
            "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
          }
        };

        var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678',
            context: ['https://hs-mittweida.de/creds', 'https://schema.org']);
        var w3cObj = jsonDecode(w3c);
        expect(w3cCredSchema.validate(w3cObj), true);
        expect(w3cObj['@context'].length, 3);
        expect(w3cObj['@context'][0], 'https://www.w3.org/2018/credentials/v1');
        expect(
            w3cObj['@context'].contains('https://hs-mittweida.de/creds'), true);
        expect(w3cObj['@context'].contains('https://schema.org'), true);
      });

      test('give credential with context as List', () {
        var plaintext = {
          '@context': ['https://schema.org'],
          "id": "did:ethr:0x12234",
          "givenName": {
            "value": "Max",
            "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
          }
        };

        var w3c =
            buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
        var w3cObj = jsonDecode(w3c);
        expect(w3cCredSchema.validate(w3cObj), true);
        expect(w3cObj['@context'].length, 2);
        expect(w3cObj['@context'][0], 'https://www.w3.org/2018/credentials/v1');
        expect(w3cObj['@context'].contains('https://schema.org'), true);
      });

      test('give credential with context as String', () {
        var plaintext = {
          '@context': 'https://schema.org',
          "id": "did:ethr:0x12234",
          "givenName": {
            "value": "Max",
            "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
          }
        };

        var w3c =
            buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
        var w3cObj = jsonDecode(w3c);
        expect(w3cCredSchema.validate(w3cObj), true);
        expect(w3cObj['@context'].length, 2);
        expect(w3cObj['@context'][0], 'https://www.w3.org/2018/credentials/v1');
        expect(w3cObj['@context'].contains('https://schema.org'), true);
      });

      test('give credential with context as unsupported type', () {
        var plaintext = {
          '@context': 23,
          "givenName": {
            "value": "Max",
            "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
          }
        };

        expect(
            () =>
                buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678'),
            throwsException);

        var plaintext2 = {
          '@context': true,
          "givenName": {
            "value": "Max",
            "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
          }
        };

        expect(
            () =>
                buildW3cCredentialwithHashes(plaintext2, 'did:ethr:0x12345678'),
            throwsException);

        var plaintext3 = {
          '@context': {'key': 'value'},
          "givenName": {
            "value": "Max",
            "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
          }
        };

        expect(
            () =>
                buildW3cCredentialwithHashes(plaintext3, 'did:ethr:0x12345678'),
            throwsException);
      });

      test('do not add a second time', () {
        var plaintext = {
          '@context': [
            'https://schema.org',
            'https://www.w3.org/2018/credentials/v1'
          ],
          "id": "did:ethr:0x12234",
          "givenName": {
            "value": "Max",
            "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
          }
        };

        var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678',
            context: 'https://schema.org');
        var w3cObj = jsonDecode(w3c);
        expect(w3cCredSchema.validate(w3cObj), true);
        expect(w3cObj['@context'].length, 2);
        expect(
            w3cObj['@context']
                .contains('https://www.w3.org/2018/credentials/v1'),
            true);
        expect(w3cObj['@context'].contains('https://schema.org'), true);
      });
    });

    test('add credential Status', () {
      var plaintext = {
        "id": "did:ethr:0x12234",
        "givenName": {
          "value": "Max",
          "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
        }
      };

      var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678',
          revocationRegistryAddress: '0x456127387');
      var w3cObj = jsonDecode(w3c);
      expect(w3cCredSchema.validate(w3cObj), true);
      expect(w3cObj.containsKey('credentialStatus'), true);
      expect(w3cObj['credentialStatus']['type'], 'EthereumRevocationList');
      expect(w3cObj['credentialStatus']['id'], '0x456127387');
    });

    test('Add issuer information', () {
      var plaintext = {
        "id": "did:ethr:0x12234",
        "givenName": {
          "value": "Max",
          "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
        }
      };

      var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678',
          revocationRegistryAddress: '0x456127387',
          issuerInformation: {
            'url': 'hs-mittweida.de',
            'name': 'Hochschule Mittweida'
          });
      var w3cObj = jsonDecode(w3c);
      Map<String, dynamic> issInfo = w3cObj['issuer'];
      expect(w3cCredSchema.validate(w3cObj), true);
      expect(issInfo.length, 3);
      expect(issInfo['id'], 'did:ethr:0x12345678');
      expect(issInfo['url'], 'hs-mittweida.de');
      expect(issInfo['name'], 'Hochschule Mittweida');
    });

    test('only issuer id', () {
      var plaintext = {
        "id": "did:ethr:0x12234",
        "givenName": {
          "value": "Max",
          "salt": "d51e87c4-6ab5-4cf0-b932-28f6962c384e"
        }
      };

      var w3c = buildW3cCredentialwithHashes(
        plaintext,
        'did:ethr:0x12345678',
        revocationRegistryAddress: '0x456127387',
      );
      var w3cObj = jsonDecode(w3c);
      var issInfo = w3cObj['issuer'];
      expect(w3cCredSchema.validate(w3cObj), true);
      expect(issInfo.runtimeType, String);
      expect(issInfo, 'did:ethr:0x12345678');
    });

    test('multiple id values', () {
      var plaintext = {
        'alumniOf': {'id': 'did:ethr:314756'}
      };
      var hashedPlaintext =
          buildPlaintextCredential(plaintext, 'did:ethr:0x452768');
      var w3c =
          buildW3cCredentialwithHashes(hashedPlaintext, 'did:ethr:0x25467');

      var w3cMap = jsonDecode(w3c);
      expect(w3cMap['credentialSubject']['id'], 'did:ethr:0x452768');
      expect(
          w3cMap['credentialSubject']['alumniOf']['id']
              .startsWith('did:ethr:0x25467'),
          false);
    });
  });

  group('compare w3c credential and Plaintext', () {
    group('show everything', () {
      test('string num bool values with no change', () {
        var values = {
          'name': 'Max',
          'age': 20,
          'height': 1.78,
          'student': true
        };
        var plaintext = buildPlaintextCredential(values, 'did:ethr:0x123456');
        var w3c =
            buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');

        expect(compareW3cCredentialAndPlaintext(w3c, plaintext), true);
      });

      test('string num bool values with change in a value', () {
        var values = {
          'name': 'Max',
          'age': 20,
          'height': 1.78,
          'student': true
        };
        var plaintext = buildPlaintextCredential(values, 'did:ethr:0x123456');
        var w3c =
            buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
        var plaintextMap = jsonDecode(plaintext);
        plaintextMap['name']['value'] = 'Lilly';
        expect(
            () => compareW3cCredentialAndPlaintext(w3c, plaintextMap),
            throwsA(predicate((dynamic e) =>
                e.message ==
                'Given hash and calculated hash do ot match at name')));
      });

      test('objects are given', () {
        var value = {
          'mother': {'name': 'Erika', 'age': 34},
          'father': {'name': 'Thorsten', 'age': 40}
        };
        var plaintext = buildPlaintextCredential(value, 'did:ethr:0x123456');
        var w3c =
            buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');

        expect(compareW3cCredentialAndPlaintext(w3c, plaintext), true);
      });

      test('objects are given and one value was manipulated', () {
        var value = {
          'mother': {'name': 'Erika', 'age': 34},
          'father': {'name': 'Thorsten', 'age': 40}
        };
        var plaintext = buildPlaintextCredential(value, 'did:ethr:0x123456');
        var w3c =
            buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
        var plainMap = jsonDecode(plaintext);
        plainMap['mother']['age']['value'] = 35;
        expect(
            () => compareW3cCredentialAndPlaintext(w3c, plainMap),
            throwsA(predicate((dynamic e) =>
                e.message ==
                'Given hash and calculated hash do ot match at age')));
      });
      test('plaintext has object in a object', () {
        var value = {
          'friend': {
            'address': {
              'postcode': '09648',
              'streetAddress': {'street': 'Main Street', 'number': 78}
            }
          }
        };

        var plaintext = buildPlaintextCredential(value, 'did:ethr:0x123456');
        var w3c =
            buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
        expect(compareW3cCredentialAndPlaintext(w3c, plaintext), true);
      });

      test('plaintext Object has List with string, num , boolean', () {
        var value = {
          'list': ['schwimmen', true, 34, 78.9]
        };
        var plaintext = buildPlaintextCredential(value, 'did:ethr:0x123456');
        var w3c =
            buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
        expect(compareW3cCredentialAndPlaintext(w3c, plaintext), true);
      });

      test(
          'plaintext Object has List with string, num , boolean and a manipulated value',
          () {
        var value = {
          'list': ['schwimmen', true, 34, 78.9]
        };
        var plaintext = buildPlaintextCredential(value, 'did:ethr:0x123456');
        var w3c =
            buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
        var plaintextMap = jsonDecode(plaintext);
        plaintextMap['list'][1]['value'] = false;
        expect(
            () => compareW3cCredentialAndPlaintext(w3c, plaintextMap),
            throwsA(predicate((dynamic e) =>
                e.message ==
                'Calculated and given Hash in List at list do not match')));
      });

      test('plaintext object has List of Objects', () {
        var value = {
          'friends': [
            {'name': 'Max', 'age': 13},
            {'name': 'Tom', 'age': 14}
          ]
        };
        var plaintext = buildPlaintextCredential(value, 'did:ethr:0x123456');
        var w3c =
            buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
        expect(compareW3cCredentialAndPlaintext(w3c, plaintext), true);
      });

      test('plaintext object has List of Objects and a wrong value', () {
        var value = {
          'friends': [
            {'name': 'Max', 'age': 13},
            {'name': 'Tom', 'age': 14}
          ]
        };
        var plaintext = buildPlaintextCredential(value, 'did:ethr:0x123456');
        var w3c =
            buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
        var plaintextMap = jsonDecode(plaintext);
        plaintextMap['friends'][1]['name']['value'] = 'Sebastian';
        expect(
            () => compareW3cCredentialAndPlaintext(w3c, plaintextMap),
            throwsA(predicate((dynamic e) =>
                e.message ==
                'Given hash and calculated hash do ot match at name')));
      });

      test('missing salt', () {
        var values = {
          'name': 'Max',
          'age': 20,
          'height': 1.78,
          'student': true
        };
        var plaintext = buildPlaintextCredential(values, 'did:ethr:0x123456');
        var w3c =
            buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
        var plaintextMap = jsonDecode(plaintext) as Map<String, dynamic>;
        plaintextMap['name'].remove('salt');
        expect(
            () => compareW3cCredentialAndPlaintext(w3c, plaintextMap),
            throwsA(predicate(
                (dynamic e) => e.message == 'malformed object with key name')));
      });

      test('missing value', () {
        var values = {
          'name': 'Max',
          'age': 20,
          'height': 1.78,
          'student': true
        };
        var plaintext = buildPlaintextCredential(values, 'did:ethr:0x123456');
        var w3c =
            buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
        var plaintextMap = jsonDecode(plaintext) as Map<String, dynamic>;
        plaintextMap['name'].remove('value');
        expect(
            () => compareW3cCredentialAndPlaintext(w3c, plaintextMap),
            throwsA(predicate(
                (dynamic e) => e.message == 'malformed object with key name')));
      });
    });
    group('only show some values (or nothing)', () {
      test(
          'key value pairs with no change (show nothing and give hash in object)',
          () {
        var values = {
          'name': 'Max',
        };
        var plaintext = buildPlaintextCredential(values, 'did:ethr:0x123456');
        var w3c =
            buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
        var plaintextMap = jsonDecode(plaintext);
        plaintextMap['name'].remove('salt');
        plaintextMap['name'].remove('value');
        expect(compareW3cCredentialAndPlaintext(w3c, plaintextMap), true);
      });

      test(
          'key value pairs with no change (show nothing and give hash as string)',
          () {
        var values = {
          'name': 'Max',
        };
        var plaintext = buildPlaintextCredential(values, 'did:ethr:0x123456');
        var w3c =
            buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
        Map<String, dynamic> plaintextMap = jsonDecode(plaintext);
        plaintextMap.remove('name');
        expect(compareW3cCredentialAndPlaintext(w3c, plaintextMap), true);
      });

      test('show one out of two', () {
        var values = {'name': 'Max', 'age': 20};
        var plaintext = buildPlaintextCredential(values, 'did:ethr:0x123456');
        var w3c =
            buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
        var plaintextMap = jsonDecode(plaintext);
        plaintextMap['name'].remove('salt');
        plaintextMap['name'].remove('value');
        expect(compareW3cCredentialAndPlaintext(w3c, plaintextMap), true);
      });

      test('show one out of two list items (hash as string)', () {
        var value = {
          'list': ['schwimmen', 78.9]
        };
        var plaintext = buildPlaintextCredential(value, 'did:ethr:0x123456');
        var w3c =
            buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
        var plaintextMap = jsonDecode(plaintext);
        var list = plaintextMap['list'] as List<dynamic>;
        list.removeAt(0);
        plaintextMap['list'] = list;
        expect(compareW3cCredentialAndPlaintext(w3c, plaintextMap), true);
      });

      test('show one out of two list items (hash as object)', () {
        var value = {
          'list': ['schwimmen', 78.9]
        };
        var plaintext = buildPlaintextCredential(value, 'did:ethr:0x123456');
        var w3c =
            buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x12345678');
        var plaintextMap = jsonDecode(plaintext);
        plaintextMap['list'][0].remove('value');
        plaintextMap['list'][0].remove('salt');
        print(plaintextMap);
        expect(compareW3cCredentialAndPlaintext(w3c, plaintextMap), true);
      });
    });
  });

  group('getIssuerDidFromCredential', () {
    test('no issuer given', () {
      var cred = {
        '@context': ['https://schema.org'],
        'credentialSubject': {'id': 'did:ethr:0x68797'}
      };
      expect(getIssuerDidFromCredential(cred), '');
    });

    test('issuer given only with id', () {
      var cred = {
        '@context': ['https://schema.org'],
        'issuer': 'did:ethr:0x7648231',
        'credentialSubject': {'id': 'did:ethr:0x68797'}
      };
      expect(getIssuerDidFromCredential(cred), 'did:ethr:0x7648231');
    });

    test('issuer given in Object', () {
      var cred = {
        '@context': ['https://schema.org'],
        'issuer': {'id': 'did:ethr:0x7648231', 'name': 'Hochschule Mittweida'},
        'credentialSubject': {'id': 'did:ethr:0x68797'}
      };
      expect(getIssuerDidFromCredential(cred), 'did:ethr:0x7648231');
    });

    test('malformed issuer (array)', () {
      var cred = {
        '@context': ['https://schema.org'],
        'issuer': ['did:ethr:0x7648231', 'Hochschule Mittweida'],
        'credentialSubject': {'id': 'did:ethr:0x68797'}
      };
      expect(getIssuerDidFromCredential(cred), '');
    });

    test('malformed issuer (num)', () {
      var cred = {
        '@context': ['https://schema.org'],
        'issuer': 123,
        'credentialSubject': {'id': 'did:ethr:0x68797'}
      };
      expect(getIssuerDidFromCredential(cred), '');
    });

    test('malformed issuer (boolean)', () {
      var cred = {
        '@context': ['https://schema.org'],
        'issuer': true,
        'credentialSubject': {'id': 'did:ethr:0x68797'}
      };
      expect(getIssuerDidFromCredential(cred), '');
    });

    test('issuer in other object embedded', () {
      var cred = {
        '@context': ['https://schema.org'],
        'key': {'issuer': true},
        'credentialSubject': {'id': 'did:ethr:0x68797'}
      };
      expect(getIssuerDidFromCredential(cred), '');
    });
  });

  group('getHolderDidFromCredential', () {
    test('holder did in credential Subject', () {
      var cred = {
        '@context': ['https://schema.org'],
        'issuer': 'did:ethr:0x8759',
        'credentialSubject': {'id': 'did:ethr:0x68797'}
      };
      expect(getHolderDidFromCredential((cred)), 'did:ethr:0x68797');
    });

    test('Holder did as id', () {
      var cred = {
        '@context': ['https://schema.org'],
        'issuer': 'did:ethr:0x8759',
        'id': 'did:ethr:0x68797'
      };
      expect(getHolderDidFromCredential((cred)), 'did:ethr:0x68797');
    });

    test('no id in credentialSubject', () {
      var cred = {
        '@context': ['https://schema.org'],
        'issuer': 'did:ethr:0x8759',
        'credentialSubject': {'age': 12}
      };
      expect(getHolderDidFromCredential((cred)), '');
    });

    test('no id in credential', () {
      var cred = {
        '@context': ['https://schema.org'],
        'issuer': 'did:ethr:0x8759'
      };
      expect(getHolderDidFromCredential((cred)), '');
    });
  });

  group('Sign and verify credential', () {
    late WalletStore wallet;
    String? w3c;

    setUp(() async {
      var dir = Directory('tests');
      if (!dir.existsSync()) {
        wallet = WalletStore('tests');
        await wallet.openBoxes('password');
        await wallet.initialize();
        await wallet.initializeIssuer();
      }
      var cred = {
        '@context': 'https://schema.org',
        'name': 'Max',
        'age': 20,
        'height': 1.78,
        'student': true
      };
      var plaintext = buildPlaintextCredential(cred, 'did:ethr:0x123456');
      w3c = buildW3cCredentialwithHashes(
          plaintext, wallet.getStandardIssuerDid());
    });

    test('check signed credential; no proof Options given; no manipulation',
        () async {
      var signed = await signCredential(wallet, w3c);
      var signedMap = jsonDecode(signed) as Map<String, dynamic>;
      expect(signedMap.containsKey('proof'), true);
      expect(signedMap['proof']['verificationMethod'],
          wallet.getStandardIssuerDid());
      expect(signedMap['proof']['type'], 'EcdsaSecp256k1RecoverySignature2020');
      expect(signedMap['proof']['proofPurpose'], 'assertionMethod');
      expect(signedMap['proof'].containsKey('created'), true);

      expect(
          await verifyCredential(signedMap,
              erc1056: erc1056, revocationRegistry: revocationRegistry),
          true);
    });

    test(
        'check signed credential; no proof Options given; with manipulation in data',
        () async {
      var signed = await signCredential(wallet, w3c);
      var signedMap = jsonDecode(signed) as Map<String, dynamic>;
      signedMap['credentialSubject']['id'] = '0x567';
      expect(signedMap.containsKey('proof'), true);
      expect(signedMap['proof']['verificationMethod'],
          wallet.getStandardIssuerDid());
      expect(signedMap['proof']['type'], 'EcdsaSecp256k1RecoverySignature2020');
      expect(signedMap['proof']['proofPurpose'], 'assertionMethod');
      expect(signedMap['proof'].containsKey('created'), true);

      expect(
          await verifyCredential(signedMap,
              erc1056: erc1056, revocationRegistry: revocationRegistry),
          false);
    });

    test(
        'check signed credential; no proof Options given; with manipulation in proof Options',
        () async {
      var signed = await signCredential(wallet, w3c);
      var signedMap = jsonDecode(signed) as Map<String, dynamic>;
      expect(signedMap.containsKey('proof'), true);
      expect(signedMap['proof']['verificationMethod'],
          wallet.getStandardIssuerDid());
      expect(signedMap['proof']['type'], 'EcdsaSecp256k1RecoverySignature2020');
      expect(signedMap['proof']['proofPurpose'], 'assertionMethod');
      expect(signedMap['proof'].containsKey('created'), true);

      signedMap['proof']['created'] = DateTime.now().toUtc().toIso8601String();

      expect(
          await verifyCredential(signedMap,
              erc1056: erc1056, revocationRegistry: revocationRegistry),
          false);
    });

    test('call verify without proof', () {
      expect(
          () async => await verifyCredential(w3c,
              erc1056: erc1056, revocationRegistry: revocationRegistry),
          throwsA(
              predicate((dynamic e) => e.message == 'no proof section found')));
    });

    group('credential revocation', () {
      test('credential was revoked', () async {
        var plaintext = {'@context': 'schema.org', 'name': 'Max', 'age': 20};
        var rev = RevocationRegistry(rpcUrl);
        var revAddress = await rev
            .deploy(await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/8'));
        var cred = buildPlaintextCredential(plaintext, ganacheDid6);
        var w3cCred = buildW3cCredentialwithHashes(cred, ganacheDid9,
            revocationRegistryAddress: revAddress);
        var signed = await signCredential(ganacheAccounts, w3cCred);

        //before revocation
        var verified = await verifyCredential(signed,
            erc1056: erc1056, revocationRegistry: revocationRegistry);
        expect(verified, true);

        //revocation
        await rev.revoke(
            await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/8'),
            ganacheDid6);

        //after revocation
        expect(
            () async => await verifyCredential(signed,
                erc1056: erc1056, revocationRegistry: revocationRegistry),
            throwsA(predicate(
                (dynamic e) => e.message == 'Credential was revoked')));
      });

      test('unknown revocation method', () async {
        var w3cMap = jsonDecode(w3c!);
        var rev = {'type': 'RevocationList2020', 'id': 'http://example.com'};
        w3cMap['credentialStatus'] = rev;
        var signed = await signCredential(wallet, w3cMap);

        expect(
            () async => await verifyCredential(signed,
                erc1056: erc1056, revocationRegistry: revocationRegistry),
            throwsA(predicate((dynamic e) =>
                e.message == 'Unknown Status-method : RevocationList2020')));
      });
    });

    test('with owner change', () async {
      var web3 = Web3Client(rpcUrl, Client());

      var signed = await signCredential(wallet, w3c);
      expect(
          await verifyCredential(signed,
              erc1056: erc1056, revocationRegistry: revocationRegistry),
          true);

      var tx = Transaction(
          from: EthereumAddress.fromHex(ganacheDid6.substring(9)),
          to: EthereumAddress.fromHex(
              wallet.getStandardIssuerDid()!.substring(9)),
          value: EtherAmount.fromUnitAndValue(EtherUnit.ether, 1));

      await web3.sendTransaction(
          EthPrivateKey.fromHex(
              await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/5')),
          tx);

      await erc1056.changeOwner((await wallet.getStandardIssuerPrivateKey())!,
          wallet.getStandardIssuerDid()!, await wallet.getNextCredentialDID());

      expect(
          await verifyCredential(signed,
              erc1056: erc1056, revocationRegistry: revocationRegistry),
          false);
    });

    tearDown(() {
      var dir = Directory('tests');
      if (dir.existsSync()) dir.delete(recursive: true);
    });
  });

  group('sign and verify presentation', () {
    late WalletStore holder;
    String? didCred1, didCred2, didCred3;
    String? plaintext1, plaintext2, plaintext3;
    String? signed1, signed2, signed3;
    setUp(() async {
      var iss1 = WalletStore('testIss1');
      await iss1.openBoxes('password1');
      await iss1.initialize();
      await iss1.initializeIssuer();

      var iss2 = WalletStore('testIss2');
      await iss2.openBoxes('password2');
      await iss2.initialize();
      await iss2.initializeIssuer();

      var iss3 = WalletStore('testIss3');
      await iss3.openBoxes('password3');
      await iss3.initialize();
      await iss3.initializeIssuer();

      holder = WalletStore('holder');
      await holder.openBoxes('passwordH');
      await holder.initialize();

      var cred1 = {
        '@context': 'https://schema.org',
        'name': 'Max Mustermann',
        'address': {
          'postalCode': '09648',
          'streetAddress': 'Am Schwanenteich 8'
        }
      };
      var cred2 = {
        '@context': 'https://schema.org',
        'grades': [
          {'course': 'Mathematik', 'grade': 1.0},
          {'course': 'Datenbanken', 'grade': 1.3}
        ]
      };
      var cred3 = {
        '@context': 'https://schema.org',
        'verein': 'Laufgruppe Döbeln',
        'rolle': 'Mitglied'
      };

      didCred1 = await holder.getNextCredentialDID();
      didCred2 = await holder.getNextCredentialDID();
      didCred3 = await holder.getNextCredentialDID();

      plaintext1 = buildPlaintextCredential(cred1, didCred1);
      plaintext2 = buildPlaintextCredential(cred2, didCred2);
      plaintext3 = buildPlaintextCredential(cred3, didCred3);

      var w3cCred1 =
          buildW3cCredentialwithHashes(plaintext1, iss1.getStandardIssuerDid());
      var w3cCred2 =
          buildW3cCredentialwithHashes(plaintext2, iss2.getStandardIssuerDid());
      var w3cCred3 =
          buildW3cCredentialwithHashes(plaintext3, iss3.getStandardIssuerDid());

      signed1 = await signCredential(iss1, w3cCred1);
      signed2 = await signCredential(iss2, w3cCred2);
      signed3 = await signCredential(iss3, w3cCred3);
    });

    test('build and verify presentation without manipulation', () async {
      var challenge = Uuid().v4();
      var presentation = await buildPresentation(
          [signed1, signed2, signed3], holder, challenge);
      var presMap = jsonDecode(presentation) as Map;
      expect(presMap.containsKey('proof'), true);
      expect(presMap['proof'] is List, true);
      expect(presMap['proof'].length, 3);

      expect(presMap.containsKey('verifiableCredential'), true);
      expect(presMap['verifiableCredential'] is List, true);
      expect(presMap['verifiableCredential'].length, 3);

      List<String?> verificationMethods = [];
      presMap['proof'].forEach((elem) {
        expect(elem.containsKey('challenge'), true);
        expect(elem['challenge'], challenge);
        verificationMethods.add(elem['verificationMethod']);
      });

      expect(verificationMethods.contains(didCred1), true);
      expect(verificationMethods.contains(didCred2), true);
      expect(verificationMethods.contains(didCred3), true);
      expect(
          await verifyPresentation(presentation, challenge,
              erc1056: erc1056, revocationRegistry: revocationRegistry),
          true);
    });

    test('one nonce/challenge is manipulated', () async {
      var challenge = Uuid().v4();
      var presentation = await buildPresentation(
          [signed1, signed2, signed3], holder, challenge);
      var presMap = jsonDecode(presentation) as Map;

      presMap['proof'][0]['challenge'] = Uuid().v4();

      expect(
          () async => await verifyPresentation(presMap, challenge,
              erc1056: erc1056, revocationRegistry: revocationRegistry),
          throwsA(predicate((dynamic e) =>
              e.message == 'a challenge do not match expected challenge')));
    });

    test('manipulated proof', () async {
      var challenge = Uuid().v4();
      var presentation = await buildPresentation(
          [signed1, signed2, signed3], holder, challenge);
      var presMap = jsonDecode(presentation) as Map;

      presMap['proof'][0]['verificationMethod'] =
          'did:ethr:0xC3d188C872e25c0370Ff3D2aA7268e2e13D11fe9';

      expect(
          () async => await verifyPresentation(presMap, challenge,
              erc1056: erc1056, revocationRegistry: revocationRegistry),
          throwsA(predicate((dynamic e) =>
              e.message ==
              'Proof for did:ethr:0xC3d188C872e25c0370Ff3D2aA7268e2e13D11fe9 could not been verified')));
    });

    test('not enough proofs', () async {
      var challenge = Uuid().v4();
      var presentation = await buildPresentation(
          [signed1, signed2, signed3], holder, challenge);
      var presMap = jsonDecode(presentation) as Map;

      presMap['proof'].removeAt(0);

      expect(
          () async => await verifyPresentation(presMap, challenge,
              erc1056: erc1056, revocationRegistry: revocationRegistry),
          throwsA(predicate(
              (dynamic e) => e.message == 'There are dids without a proof')));
    });

    test('add additional proofs', () async {
      var challenge = Uuid().v4();
      var newDID = await holder.getNextConnectionDID();
      var presentation = await buildPresentation(
          [signed1, signed2, signed3], holder, challenge,
          additionalDids: [newDID]);
      var presMap = jsonDecode(presentation) as Map;
      List<dynamic> proofs = presMap['proof'];
      expect(proofs.length, 4);
      expect(
          await verifyPresentation(presentation, challenge,
              erc1056: erc1056, revocationRegistry: revocationRegistry),
          true);
    });

    test('credential could not been verified (verifyCredential returns false)',
        () async {
      var challenge = Uuid().v4();
      var presentation = await buildPresentation(
          [signed1, signed2, signed3], holder, challenge);
      var presMap = jsonDecode(presentation) as Map;
      presMap['verifiableCredential'][0]['issuer'] =
          await holder.getNextCredentialDID();

      expect(
          () async => await verifyPresentation(presMap, challenge,
              erc1056: erc1056, revocationRegistry: revocationRegistry),
          throwsA(predicate((dynamic e) =>
              e.message == 'A credential could not been verified')));
    });

    test('one holder did was changed', () async {
      var challenge = Uuid().v4();
      var presentation1 = await buildPresentation(
          [signed1, signed2, signed3], holder, challenge);
      expect(
          await verifyPresentation(presentation1, challenge,
              erc1056: erc1056, revocationRegistry: revocationRegistry),
          true);

      var web3 = Web3Client(rpcUrl, Client());

      var tx = Transaction(
          from: EthereumAddress.fromHex(ganacheDid6.substring(9)),
          to: EthereumAddress.fromHex(didCred1!.substring(9)),
          value: EtherAmount.fromUnitAndValue(EtherUnit.ether, 1));

      await web3.sendTransaction(
          EthPrivateKey.fromHex(
              await ganacheAccounts.getPrivateKey('m/44\'/60\'/0\'/0/5')),
          tx);
      var newDid = await holder.getNextCredentialDID();
      await erc1056.changeOwner(
          (await holder.getPrivateKeyForCredentialDid(didCred1!))!,
          didCred1!,
          newDid);

      var newPath = holder.getCredential(newDid)!.hdPath;
      holder.storeCredential('', '', newPath, credDid: didCred1);
      var presentation2 = await buildPresentation(
          [signed1, signed2, signed3], holder, challenge);
      expect(
          await verifyPresentation(presentation2, challenge,
              erc1056: erc1056, revocationRegistry: revocationRegistry),
          true);
    });

    group('undisclosed Credentials in presentation', () {
      String? undisclosed1, undisclosed2, undisclosed3;
      setUp(() {
        undisclosed1 =
            discloseValues(plaintext1, ['name', 'address.streetAddress']);
        undisclosed2 = discloseValues(plaintext2, ['grades.1']);
        undisclosed3 = discloseValues(plaintext3, ['rolle']);
      });

      test('all without manipulation', () async {
        var challenge = Uuid().v4();
        var presentation = await buildPresentation(
            [signed1, signed2, signed3], holder, challenge,
            disclosedCredentials: [undisclosed1, undisclosed2, undisclosed3]);
        Map<String, dynamic> presMap = jsonDecode(presentation);
        expect(presMap.containsKey('disclosedCredentials'), true);
        expect(presMap['disclosedCredentials'].length, 3);
        expect(await verifyPresentation(presentation, challenge), true);
      });
    });

    tearDown(() {
      var holder = Directory('holder');
      if (holder.existsSync()) holder.delete(recursive: true);
      var iss1 = Directory('testIss1');
      if (iss1.existsSync()) iss1.delete(recursive: true);
      var iss2 = Directory('testIss2');
      if (iss2.existsSync()) iss2.delete(recursive: true);
      var iss3 = Directory('testIss3');
      if (iss3.existsSync()) iss3.delete(recursive: true);
    });
  });

  group('sign random String', () {
    test('sign without any manipulation or key rotation', () async {
      String toSign = 'Its a String';
      WalletStore w = WalletStore('tests');
      await w.openBoxes('password');
      await w.initialize();
      var did = await w.getNextCredentialDID();
      var jws = await signStringOrJson(w, did, toSign);

      var verified = await verifyStringSignature(jws, did,
          erc1056: erc1056, toSign: toSign);

      expect(verified, true);

      var dir = Directory('tests');
      if (dir.existsSync()) dir.delete(recursive: true);
    });
  });

  group('disclose Credential', () {
    test('disclose one single value ', () {
      var cred = {'givenName': 'Max', 'familyName': 'Mustermann'};
      var plaintext = buildPlaintextCredential(cred, 'did:ethr:0x123456');
      Map<String, dynamic> disclosed =
          jsonDecode(discloseValues(plaintext, ['familyName']));

      var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x687236892');
      expect(compareW3cCredentialAndPlaintext(w3c, disclosed), true);

      Map<String, dynamic> givenName =
          disclosed['givenName'] as Map<String, dynamic>;
      var familyName = disclosed['familyName'];

      expect(givenName.keys, ['value', 'salt']);
      expect(familyName, null);
    });

    test('disclose value in Object', () {
      var cred = {
        'address': {'street': 'Main Street', 'city': 'London'}
      };

      var plaintext = buildPlaintextCredential(cred, 'did:ethr:0x123456');
      var disclosed = jsonDecode(discloseValues(plaintext, ['address.street']));

      var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x687236892');
      expect(compareW3cCredentialAndPlaintext(w3c, disclosed), true);

      var street = disclosed['address']['street'];
      Map<String, dynamic> city = disclosed['address']['city'];

      expect(street, null);
      expect(city.keys, ['value', 'salt']);
    });

    test('disclose all values in Object (short notation)', () {
      var cred = {
        'address': {'street': 'Main Street', 'city': 'London'}
      };

      var plaintext = buildPlaintextCredential(cred, 'did:ethr:0x123456');
      var disclosed = jsonDecode(discloseValues(plaintext, ['address']));

      var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x687236892');
      expect(compareW3cCredentialAndPlaintext(w3c, disclosed), true);

      var street = disclosed['address']['street'];
      var city = disclosed['address']['city'];

      expect(street, null);
      expect(city, null);
    });

    test('disclose all values in Object ', () {
      var cred = {
        'address': {'street': 'Main Street', 'city': 'London'}
      };

      var plaintext = buildPlaintextCredential(cred, 'did:ethr:0x123456');
      var disclosed = jsonDecode(
          discloseValues(plaintext, ['address.street', 'address.city']));

      var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x687236892');
      expect(compareW3cCredentialAndPlaintext(w3c, disclosed), true);

      var street = disclosed['address']['street'];
      var city = disclosed['address']['city'];

      expect(street, null);
      expect(city, null);
    });

    test('disclose value in simple List', () {
      var cred = {
        'hobby': ['reiten', 'schwimmen', 'lesen']
      };
      var plaintext = buildPlaintextCredential(cred, 'did:ethr:0x123456');
      var disclosed =
          jsonDecode(discloseValues(plaintext, ['hobby.0', 'hobby.2']));

      var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x687236892');
      expect(compareW3cCredentialAndPlaintext(w3c, disclosed), true);

      Map<String, dynamic> schwimmen = disclosed['hobby'][0];

      expect(disclosed['hobby'].length, 1);
      expect(schwimmen.keys, ['value', 'salt']);
    });

    test('disclose all values in simple List', () {
      var cred = {
        'hobby': ['reiten', 'schwimmen', 'lesen']
      };
      var plaintext = buildPlaintextCredential(cred, 'did:ethr:0x123456');
      var disclosed = jsonDecode(discloseValues(plaintext, ['hobby']));

      var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x687236892');
      expect(compareW3cCredentialAndPlaintext(w3c, disclosed), true);

      expect(disclosed['hobby'].length, 0);
    });

    test('disclose values in List with Objects from different Objects', () {
      var cred = {
        'friends': [
          {'givenName': 'Timo', 'familyName': 'Schulz'},
          {'givenName': 'Jan', 'familyName': 'Bauer'},
          {'givenName': 'Max', 'familyName': 'Mustermann'}
        ]
      };
      var plaintext = buildPlaintextCredential(cred, 'did:ethr:0x123456');
      var disclosed = jsonDecode(discloseValues(
          plaintext, ['friends.0.givenName', 'friends.1.familyName']));

      var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x687236892');
      expect(compareW3cCredentialAndPlaintext(w3c, disclosed), true);

      var f0GivenName = disclosed['friends'][0]['givenName'];
      Map<String, dynamic> f0familyName = disclosed['friends'][0]['familyName'];
      Map<String, dynamic> f1GivenName = disclosed['friends'][1]['givenName'];
      var f1familyName = disclosed['friends'][1]['familyName'];
      Map<String, dynamic> f2GivenName = disclosed['friends'][2]['givenName'];
      Map<String, dynamic> f2familyName = disclosed['friends'][2]['familyName'];

      expect(f0GivenName, null);
      expect(f0familyName.keys, ['value', 'salt']);
      expect(f1GivenName.keys, ['value', 'salt']);
      expect(f1familyName, null);
      expect(f2GivenName.keys, ['value', 'salt']);
      expect(f2familyName.keys, ['value', 'salt']);
    });

    test('disclose values in List with Objects from same Objects', () {
      var cred = {
        'friends': [
          {'givenName': 'Timo', 'familyName': 'Schulz'},
          {'givenName': 'Jan', 'familyName': 'Bauer'},
          {'givenName': 'Max', 'familyName': 'Mustermann'}
        ]
      };
      var plaintext = buildPlaintextCredential(cred, 'did:ethr:0x123456');
      var disclosed = jsonDecode(discloseValues(
          plaintext, ['friends.0.givenName', 'friends.0.familyName']));

      var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x687236892');
      expect(compareW3cCredentialAndPlaintext(w3c, disclosed), true);

      expect(disclosed['friends'].length, 3);

      Map<String, dynamic> f1GivenName = disclosed['friends'][1]['givenName'];
      Map<String, dynamic> f1familyName = disclosed['friends'][1]['familyName'];
      Map<String, dynamic> f2GivenName = disclosed['friends'][2]['givenName'];
      Map<String, dynamic> f2familyName = disclosed['friends'][2]['familyName'];

      expect(disclosed['friends'][0].length, 0);
      expect(f1GivenName.keys, ['value', 'salt']);
      expect(f1familyName.keys, ['value', 'salt']);
      expect(f2GivenName.keys, ['value', 'salt']);
      expect(f2familyName.keys, ['value', 'salt']);
    });

    test(
        'disclose values in List with Objects from same Object (short notation)',
        () {
      var cred = {
        'friends': [
          {'givenName': 'Timo', 'familyName': 'Schulz'},
          {'givenName': 'Jan', 'familyName': 'Bauer'},
          {'givenName': 'Max', 'familyName': 'Mustermann'}
        ]
      };
      var plaintext = buildPlaintextCredential(cred, 'did:ethr:0x123456');
      var disclosed = jsonDecode(discloseValues(plaintext, ['friends.0']));

      var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x687236892');
      expect(compareW3cCredentialAndPlaintext(w3c, disclosed), true);

      expect(disclosed['friends'].length, 3);

      Map<String, dynamic> f1GivenName = disclosed['friends'][1]['givenName'];
      Map<String, dynamic> f1familyName = disclosed['friends'][1]['familyName'];
      Map<String, dynamic> f2GivenName = disclosed['friends'][2]['givenName'];
      Map<String, dynamic> f2familyName = disclosed['friends'][2]['familyName'];

      expect(disclosed['friends'][0].length, 0);
      expect(f1GivenName.keys, ['value', 'salt']);
      expect(f1familyName.keys, ['value', 'salt']);
      expect(f2GivenName.keys, ['value', 'salt']);
      expect(f2familyName.keys, ['value', 'salt']);
    });

    test('disclose all values from one Object in List and one from another',
        () {
      var cred = {
        'friends': [
          {'givenName': 'Timo', 'familyName': 'Schulz'},
          {'givenName': 'Jan', 'familyName': 'Bauer'},
          {'givenName': 'Max', 'familyName': 'Mustermann'}
        ]
      };
      var plaintext = buildPlaintextCredential(cred, 'did:ethr:0x123456');
      var disclosed = jsonDecode(
          discloseValues(plaintext, ['friends.0', 'friends.1.familyName']));

      var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x687236892');
      expect(compareW3cCredentialAndPlaintext(w3c, disclosed), true);

      expect(disclosed['friends'].length, 3);

      Map<String, dynamic> f1GivenName = disclosed['friends'][1]['givenName'];
      var f1familyName = disclosed['friends'][1]['familyName'];
      Map<String, dynamic> f2GivenName = disclosed['friends'][2]['givenName'];
      Map<String, dynamic> f2familyName = disclosed['friends'][2]['familyName'];

      expect(disclosed['friends'][0].length, 0);
      expect(f1GivenName.keys, ['value', 'salt']);
      expect(f1familyName, null);
      expect(f2GivenName.keys, ['value', 'salt']);
      expect(f2familyName.keys, ['value', 'salt']);
    });

    test('disclose all values in List with Objects', () {
      var cred = {
        'friends': [
          {'givenName': 'Timo', 'familyName': 'Schulz'},
          {'givenName': 'Jan', 'familyName': 'Bauer'},
          {'givenName': 'Max', 'familyName': 'Mustermann'}
        ]
      };
      var plaintext = buildPlaintextCredential(cred, 'did:ethr:0x123456');
      var disclosed = jsonDecode(discloseValues(plaintext, ['friends']));

      var w3c = buildW3cCredentialwithHashes(plaintext, 'did:ethr:0x687236892');
      expect(compareW3cCredentialAndPlaintext(w3c, disclosed), true);

      expect(disclosed['friends'][0].length, 0);
      expect(disclosed['friends'][1].length, 0);
      expect(disclosed['friends'][2].length, 0);
    });
  });

  group('get json-Paths', () {
    test('simple credential', () {
      var cred = {'name': 'Mustermann', 'surname': 'Max'};
      var paths = getAllJsonPathsOfCredential(cred);
      expect(paths.length, 2);
      expect(paths.contains('name'), true);
      expect(paths.contains('surname'), true);
    });

    test('credential with Object', () {
      var cred = {
        'address': {'street': 'Main Street', 'postalCode': 09661}
      };
      var paths = getAllJsonPathsOfCredential(cred);
      expect(paths.length, 2);
      expect(paths.contains('address.street'), true);
      expect(paths.contains('address.postalCode'), true);
    });

    test('with simple array', () {
      var cred = {
        'drivingClasses': ['AM', 'L', 'B']
      };
      var paths = getAllJsonPathsOfCredential(cred);
      expect(paths.length, 3);
      expect(paths.contains('drivingClasses.0'), true);
      expect(paths.contains('drivingClasses.1'), true);
      expect(paths.contains('drivingClasses.2'), true);
    });

    test('Array with Objects', () {
      var cred = {
        'friends': [
          {'name': 'Lukas', 'age': 19},
          {'name': 'Bastian', 'age': 18}
        ]
      };
      var paths = getAllJsonPathsOfCredential(cred);
      expect(paths.length, 4);
      expect(paths.contains('friends.0.name'), true);
      expect(paths.contains('friends.1.name'), true);
      expect(paths.contains('friends.0.age'), true);
      expect(paths.contains('friends.1.age'), true);
    });
  });

  group('use other network', () {
    late WalletStore wallet;
    late Erc1056 ercWithId;

    setUp(() async {
      wallet = WalletStore('other');
      await wallet.openBoxes();
      await wallet.initialize(network: 'ropsten');
      await wallet.initializeIssuer();
      ercWithId = Erc1056(rpcUrl,
          networkNameOrId: 'ropsten',
          contractAddress: '0x0eE301c92471234038E320153A7F650ab9a72e28');
    });

    test('next did', () async {
      var did = await wallet.getNextCredentialDID();
      expect(did.startsWith('did:ethr:ropsten'), true);
    });

    test('sign String', () async {
      var toSign = 'test';
      var didToSignWith = await wallet.getNextConnectionDID();
      var jws = await signStringOrJson(wallet, didToSignWith, toSign);
      var checked =
          await verifyStringSignature(jws, didToSignWith, erc1056: ercWithId);
      expect(checked, true);
    });

    test('sign a credential', () async {
      var cred = {'@context': 'schema.org', 'name': 'Max', 'age': 23};
      var holderDid = await wallet.getNextCredentialDID();
      var plain = buildPlaintextCredential(cred, holderDid);
      expect(
          wallet.getStandardIssuerDid()!.startsWith('did:ethr:ropsten'), true);
      var w3c =
          buildW3cCredentialwithHashes(plain, wallet.getStandardIssuerDid());
      var signed = await signCredential(wallet, w3c);
      expect(await verifyCredential(signed, erc1056: ercWithId), true);
    });

    tearDown(() {
      if (Directory('other').existsSync()) {
        Directory('other').delete(recursive: true);
      }
    });
  });

  group('Presentation Definition', () {
    Map<String, dynamic> vc1 = {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "http://example.gov/credentials/3732",
      "type": ["VerifiableCredential", "UniversityDegreeCredential"],
      "issuer": "https://example.edu",
      "issuanceDate": "2010-01-01T19:23:24Z",
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "degree": {
          "type": "BachelorDegree",
          "name": "Bachelor of Science and Arts"
        }
      },
      "proof": {
        "type": "Ed25519Signature2020",
        "created": "2021-11-13T18:19:39Z",
        "verificationMethod": "https://example.edu/issuers/14#key-1",
        "proofPurpose": "assertionMethod",
        "proofValue":
            "z58DAdFfa9SkqZMVPxAQpic7ndSayn1PzZs6ZjWp1CktyGesjuTSwRdoWhAfGFCF5bppETSTojQCrfFPP2oumHKtz"
      }
    };

    Map<String, dynamic> vc2 = {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "http://example.gov/credentials/3732",
      "type": ["VerifiableCredential", "UniversityDegreeCredential"],
      "issuer": "https://example2.edu",
      "issuanceDate": "2010-01-01T19:23:24Z",
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        'type': 'NameAddress',
        'familyName': 'Mustermann',
        'givenName': 'Max',
        'address': {
          'streetAddress': 'Am Schwanenteich 8',
          'postalCode': '09648'
        }
      },
      "proof": {
        "type": "Ed25519Signature2020",
        "created": "2021-11-13T18:19:39Z",
        "verificationMethod": "https://example.edu/issuers/14#key-1",
        "proofPurpose": "assertionMethod",
        "proofValue":
            "z58DAdFfa9SkqZMVPxAQpic7ndSayn1PzZs6ZjWp1CktyGesjuTSwRdoWhAfGFCF5bppETSTojQCrfFPP2oumHKtz"
      }
    };

    test('simple Request (filter issuer)', () {
      Map<String, dynamic> presentationDefinition = {
        "presentation_definition": {
          "id": "Scalable trust example",
          "input_descriptors": [
            {
              "id": "any type of credit card from any bank",
              "name": "any type of credit card from any bank",
              "purpose": "Please provide your student Card from the university",
              "constraints": {
                "fields": [
                  {
                    "path": [r"$..issuer"],
                    "filter": {
                      "type": "string",
                      "pattern": "https://example2.edu"
                    }
                  }
                ]
              }
            }
          ]
        }
      };

      var result = searchCredentialsForPresentationDefinition(
          [vc1, vc2], PresentationDefinition.fromJson(presentationDefinition));
      expect(result.length, 1);
    });

    test('filter issuer id (plain or object)', () {
      var vc3 = {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": "http://example.gov/credentials/3732",
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "issuer": {'id': "https://example2.edu"},
        "issuanceDate": "2010-01-01T19:23:24Z",
        "credentialSubject": {
          "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
          "degree": {
            "type": "BachelorDegree",
            "name": "Bachelor of Science and Arts"
          }
        },
        "proof": {
          "type": "Ed25519Signature2020",
          "created": "2021-11-13T18:19:39Z",
          "verificationMethod": "https://example.edu/issuers/14#key-1",
          "proofPurpose": "assertionMethod",
          "proofValue":
              "z58DAdFfa9SkqZMVPxAQpic7ndSayn1PzZs6ZjWp1CktyGesjuTSwRdoWhAfGFCF5bppETSTojQCrfFPP2oumHKtz"
        }
      };
      Map<String, dynamic> presentationDefinition = {
        "presentation_definition": {
          "id": "Scalable trust example",
          "input_descriptors": [
            {
              "id": "any type of credit card from any bank",
              "name": "any type of credit card from any bank",
              "purpose": "Please provide your student Card from the university",
              "constraints": {
                "fields": [
                  {
                    "path": [r"$.issuer", r'$.issuer.id'],
                    "filter": {
                      "type": "string",
                      "pattern": "https://example2.edu"
                    }
                  }
                ]
              }
            }
          ]
        }
      };
      var result = searchCredentialsForPresentationDefinition(
          [vc1, vc3], PresentationDefinition.fromJson(presentationDefinition));
      expect(result.length, 1);
    });
  });
}
