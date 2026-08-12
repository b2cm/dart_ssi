import 'package:dart_ssi/oid.dart';
import 'package:test/test.dart';

void main() {
  group('Credential Offer', () {
    test('example draft 13 json', () {
      var data = {
        "credential_issuer": "https://credential-issuer.example.com",
        "credential_configuration_ids": [
          "UniversityDegreeCredential",
          "org.iso.18013.5.1.mDL"
        ],
        "grants": {
          "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
            "pre-authorized_code": "oaKazRN8I0IbtZ0C7JuMn5",
            "tx_code": {
              "length": 4,
              "input_mode": "numeric",
              "description":
                  "Please provide the one-time code that was sent via e-mail"
            }
          }
        }
      };

      var offer = OidCredentialOffer.fromJson(data);
      var offer2 = OidCredentialOffer.fromJson(offer.toJson());

      expect(offer.credentialIssuer, offer2.credentialIssuer);
      expect(
          offer.credentialConfigurationIds, offer2.credentialConfigurationIds);

      expect(offer.grants?.length, 1);
      expect(
          offer.grants?.containsKey(
              'urn:ietf:params:oauth:grant-type:pre-authorized_code'),
          isTrue);

      expect(offer.grants?.length, offer2.grants?.length);
      var preAuthGrant =
          offer.grants!['urn:ietf:params:oauth:grant-type:pre-authorized_code']
              as PreAuthCodeGrant;
      var preAuthGrant2 =
          offer2.grants!['urn:ietf:params:oauth:grant-type:pre-authorized_code']
              as PreAuthCodeGrant;

      expect(preAuthGrant.txCode, true);
      expect(preAuthGrant.preAuthCode, 'oaKazRN8I0IbtZ0C7JuMn5');
      expect(preAuthGrant2.txCode, true);
      expect(preAuthGrant2.preAuthCode, 'oaKazRN8I0IbtZ0C7JuMn5');
    });

    test('example draft 13 link', () {
      var link =
          'https://example.com/credential_offer?credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com%22,%22credentials%22:%5B%22UniversityDegree_JWT%22,%22org.iso.18013.5.1.mDL%22%5D,%22grants%22:%7B%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:%7B%22pre-authorized_code%22:%22oaKazRN8I0IbtZ0C7JuMn5%22,%22tx_code%22:%7B%7D%7D%7D%7D';

      var offer = OidCredentialOffer.fromUri(link);
      var offer2 = OidCredentialOffer.fromJson(offer.toJson());

      expect(offer.credentialIssuer, offer2.credentialIssuer);
      expect(
          offer.credentialConfigurationIds, offer2.credentialConfigurationIds);
      expect(offer.credentials, offer2.credentials);

      expect(offer.grants?.length, 1);
      expect(
          offer.grants?.containsKey(
              'urn:ietf:params:oauth:grant-type:pre-authorized_code'),
          isTrue);

      var preAuthGrant =
          offer.grants!['urn:ietf:params:oauth:grant-type:pre-authorized_code']
              as PreAuthCodeGrant;
      var preAuthGrant2 =
          offer2.grants!['urn:ietf:params:oauth:grant-type:pre-authorized_code']
              as PreAuthCodeGrant;

      expect(preAuthGrant.txCode, true);
      expect(preAuthGrant.preAuthCode, 'oaKazRN8I0IbtZ0C7JuMn5');
      expect(preAuthGrant2.txCode, true);
      expect(preAuthGrant2.preAuthCode, 'oaKazRN8I0IbtZ0C7JuMn5');
    });

    test('example draft 12 json', () {
      var data = {
        "credential_issuer": "https://credential-issuer.example.com",
        "credentials": ["UniversityDegreeCredential", "org.iso.18013.5.1.mDL"],
        "grants": {
          "authorization_code": {"issuer_state": "eyJhbGciOiJSU0Et...FYUaBy"},
          "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
            "pre-authorized_code": "adhjhdjajkdkhjhdj",
            "user_pin_required": true
          }
        }
      };

      var offer = OidCredentialOffer.fromJson(data);
      var offer2 = OidCredentialOffer.fromJson(offer.toJson());

      expect(offer.credentialIssuer, offer2.credentialIssuer);
      expect(
          offer.credentialConfigurationIds, offer2.credentialConfigurationIds);
      expect(offer.credentials, offer2.credentials);

      expect(offer.grants?.length, 2);
      expect(offer.grants?.length, offer2.grants?.length);

      expect(offer.grants?.keys, offer2.grants?.keys);

      expect(
          offer.grants?.containsKey(
              'urn:ietf:params:oauth:grant-type:pre-authorized_code'),
          isTrue);
      expect(offer.grants?.containsKey('authorization_code'), isTrue);

      var preAuthGrant =
          offer.grants!['urn:ietf:params:oauth:grant-type:pre-authorized_code']
              as PreAuthCodeGrant;
      var preAuthGrant2 =
          offer2.grants!['urn:ietf:params:oauth:grant-type:pre-authorized_code']
              as PreAuthCodeGrant;

      expect(preAuthGrant.txCode, true);
      expect(preAuthGrant.preAuthCode, 'adhjhdjajkdkhjhdj');
      expect(preAuthGrant2.txCode, true);
      expect(preAuthGrant2.preAuthCode, 'adhjhdjajkdkhjhdj');
    });

    test('example draft 12 link', () {
      var data =
          'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com%22,%22credentials%22:%5B%22UniversityDegree_JWT%22,%7B%22format%22:%22mso_mdoc%22,%22doctype%22:%22org.iso.18013.5.1.mDL%22%7D%5D,%22grants%22:%7B%22authorization_code%22:%7B%22issuer_state%22:%22eyJhbGciOiJSU0Et...FYUaBy%22%7D,%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:%7B%22pre-authorized_code%22:%22adhjhdjajkdkhjhdj%22,%22user_pin_required%22:true%7D%7D%7D';

      var offer = OidCredentialOffer.fromUri(data);
      var offer2 = OidCredentialOffer.fromJson(offer.toJson());

      expect(offer.credentialIssuer, offer2.credentialIssuer);
      expect(
          offer.credentialConfigurationIds, offer2.credentialConfigurationIds);
      expect(offer.credentials?.length, offer2.credentials?.length);

      expect(offer.grants?.length, 2);
      expect(offer.grants?.length, offer2.grants?.length);

      expect(offer.grants?.keys, offer2.grants?.keys);

      expect(
          offer.grants?.containsKey(
              'urn:ietf:params:oauth:grant-type:pre-authorized_code'),
          isTrue);
      expect(offer.grants?.containsKey('authorization_code'), isTrue);

      var preAuthGrant =
          offer.grants!['urn:ietf:params:oauth:grant-type:pre-authorized_code']
              as PreAuthCodeGrant;
      var preAuthGrant2 =
          offer2.grants!['urn:ietf:params:oauth:grant-type:pre-authorized_code']
              as PreAuthCodeGrant;

      expect(preAuthGrant.txCode, true);
      expect(preAuthGrant.preAuthCode, 'adhjhdjajkdkhjhdj');
      expect(preAuthGrant2.txCode, true);
      expect(preAuthGrant2.preAuthCode, 'adhjhdjajkdkhjhdj');
    });

    test('example draft 11 json', () {
      var data = {
        "credential_issuer": "https://credential-issuer.example.com",
        "credentials": [
          "UniversityDegree_JWT",
          {"format": "mso_mdoc", "doctype": "org.iso.18013.5.1.mDL"}
        ],
        "grants": {
          "authorization_code": {"issuer_state": "eyJhbGciOiJSU0Et...FYUaBy"},
          "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
            "pre-authorized_code": "adhjhdjajkdkhjhdj",
            "user_pin_required": true
          }
        }
      };

      var offer = OidCredentialOffer.fromJson(data);
      var offer2 = OidCredentialOffer.fromJson(offer.toJson());

      expect(offer.credentialIssuer, offer2.credentialIssuer);
      expect(
          offer.credentialConfigurationIds, offer2.credentialConfigurationIds);
      expect(offer.credentials?.length, offer2.credentials?.length);

      expect(offer.grants?.length, 2);
      expect(offer.grants?.length, offer2.grants?.length);

      expect(offer.grants?.keys, offer2.grants?.keys);

      expect(
          offer.grants?.containsKey(
              'urn:ietf:params:oauth:grant-type:pre-authorized_code'),
          isTrue);
      expect(offer.grants?.containsKey('authorization_code'), isTrue);

      var preAuthGrant =
          offer.grants!['urn:ietf:params:oauth:grant-type:pre-authorized_code']
              as PreAuthCodeGrant;
      var preAuthGrant2 =
          offer2.grants!['urn:ietf:params:oauth:grant-type:pre-authorized_code']
              as PreAuthCodeGrant;

      expect(preAuthGrant.txCode, true);
      expect(preAuthGrant.preAuthCode, 'adhjhdjajkdkhjhdj');
      expect(preAuthGrant2.txCode, true);
      expect(preAuthGrant2.preAuthCode, 'adhjhdjajkdkhjhdj');
    });

    test('example draft 11 json, jwt_vc_json', () {
      var data = {
        "credential_issuer": "https://credential-issuer.example.com",
        "credentials": [
          {
            "format": "jwt_vc_json",
            "types": ["VerifiableCredential", "UniversityDegreeCredential"]
          }
        ],
        "grants": {
          "authorization_code": {"issuer_state": "eyJhbGciOiJSU0Et...FYUaBy"}
        }
      };

      var offer = OidCredentialOffer.fromJson(data);
      var offer2 = OidCredentialOffer.fromJson(offer.toJson());

      expect(offer.credentialIssuer, offer2.credentialIssuer);
      expect(
          offer.credentialConfigurationIds, offer2.credentialConfigurationIds);
      expect(offer.credentials?.length, offer2.credentials?.length);

      expect(offer.grants?.length, 1);
      expect(offer.grants?.length, offer2.grants?.length);

      expect(offer.grants?.keys, offer2.grants?.keys);

      expect(offer.grants?.containsKey('authorization_code'), isTrue);

      var authGrant =
          offer.grants!['authorization_code'] as AuthorizationCodeGrant;
      var authGrant2 =
          offer2.grants!['authorization_code'] as AuthorizationCodeGrant;

      expect(authGrant.issuerState, 'eyJhbGciOiJSU0Et...FYUaBy');
      expect(authGrant2.issuerState, 'eyJhbGciOiJSU0Et...FYUaBy');
    });

    test('example draft 11 link', () {
      var data =
          'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com %22,%22credentials%22:%5B%7B%22format%22:%22jwt_vc_json%22,%22types%22:%5B%22VerifiableCredential%22,%22UniversityDegreeCredential%22%5D%7D%5D,%22issuer_state%22:%22eyJhbGciOiJSU0Et...FYUaBy%22%7D';

      var offer = OidCredentialOffer.fromUri(data);
      var offer2 = OidCredentialOffer.fromJson(offer.toJson());

      expect(offer.credentialIssuer, offer2.credentialIssuer);
      expect(
          offer.credentialConfigurationIds, offer2.credentialConfigurationIds);
      expect(offer.credentials?.length, offer2.credentials?.length);

      expect(offer.grants, null);
      expect(offer.grants, offer2.grants);
    });
  });

  group('Token Response', () {
    test('draft 13', () {
      var data = {
        "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
        "token_type": "bearer",
        "expires_in": 86400,
        "c_nonce": "tZignsnFbp",
        "c_nonce_expires_in": 86400,
        "authorization_details": [
          {
            "type": "openid_credential",
            "credential_configuration_id": "UniversityDegreeCredential",
            "credential_identifiers": [
              "CivilEngineeringDegree-2023",
              "ElectricalEngineeringDegree-2023"
            ]
          }
        ]
      };

      var tokenResponse = OidTokenResponse.fromJson(data);
      print(tokenResponse);
      var tokenResponse2 = OidTokenResponse.fromJson(tokenResponse.toJson());

      expect(tokenResponse.accessToken, tokenResponse2.accessToken);
      expect(tokenResponse.tokenType, tokenResponse2.tokenType);
      expect(tokenResponse.expiresIn, tokenResponse2.expiresIn);
      expect(tokenResponse.cNonce, tokenResponse2.cNonce);
      expect(tokenResponse.cNonceExpiresIn, tokenResponse2.cNonceExpiresIn);

      expect(tokenResponse.authorizationDetails?.length,
          tokenResponse2.authorizationDetails?.length);
    });

    test('draft 12', () {
      var data = {
        "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
        "token_type": "bearer",
        "expires_in": 86400,
        "c_nonce": "tZignsnFbp",
        "c_nonce_expires_in": 86400,
        "authorization_details": [
          {
            "type": "openid_credential",
            "format": "jwt_vc_json",
            "credential_definition": {
              "type": ["VerifiableCredential", "UniversityDegreeCredential"]
            },
            "credential_identifiers": [
              "CivilEngineeringDegree-2023",
              "ElectricalEngineeringDegree-2023"
            ]
          }
        ]
      };

      var tokenResponse = OidTokenResponse.fromJson(data);
      print(tokenResponse);
      var tokenResponse2 = OidTokenResponse.fromJson(tokenResponse.toJson());

      expect(tokenResponse.accessToken, tokenResponse2.accessToken);
      expect(tokenResponse.tokenType, tokenResponse2.tokenType);
      expect(tokenResponse.expiresIn, tokenResponse2.expiresIn);
      expect(tokenResponse.cNonce, tokenResponse2.cNonce);
      expect(tokenResponse.cNonceExpiresIn, tokenResponse2.cNonceExpiresIn);

      expect(tokenResponse.authorizationDetails?.length,
          tokenResponse2.authorizationDetails?.length);

      var detail = tokenResponse.authorizationDetails!.first;
      var detail2 = tokenResponse2.authorizationDetails!.first;
      expect(detail.type, detail2.type);
      expect(detail.format, detail2.format);
      expect(detail.credentialType, detail2.credentialType);
    });

    test('draft 11', () {
      var data = {
        "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
        "token_type": "bearer",
        "expires_in": 86400,
        "c_nonce": "tZignsnFbp",
        "c_nonce_expires_in": 86400
      };

      var tokenResponse = OidTokenResponse.fromJson(data);
      print(tokenResponse);
      var tokenResponse2 = OidTokenResponse.fromJson(tokenResponse.toJson());

      expect(tokenResponse.accessToken, tokenResponse2.accessToken);
      expect(tokenResponse.tokenType, tokenResponse2.tokenType);
      expect(tokenResponse.expiresIn, tokenResponse2.expiresIn);
      expect(tokenResponse.cNonce, tokenResponse2.cNonce);
      expect(tokenResponse.cNonceExpiresIn, tokenResponse2.cNonceExpiresIn);

      expect(tokenResponse.authorizationDetails?.length,
          tokenResponse2.authorizationDetails?.length);
    });
  });

  group('issuer metadata', () {
    test('draft 11, jwt vc json', () {
      var data = {
        "credential_issuer": "https://credential-issuer.example.com",
        "authorization_servers": ["https://server.example.com"],
        "credential_endpoint": "https://credential-issuer.example.com",
        "batch_credential_endpoint":
            "https://credential-issuer.example.com/batch_credential",
        "deferred_credential_endpoint":
            "https://credential-issuer.example.com/deferred_credential",
        "display": [
          {"name": "Example University", "locale": "en-US"},
          {"name": "Example Université", "locale": "fr-FR"}
        ],
        'credentials_supported': [
          {
            "format": "jwt_vc_json",
            "id": "UniversityDegree_JWT",
            "types": ["VerifiableCredential", "UniversityDegreeCredential"],
            "cryptographic_binding_methods_supported": ["did"],
            "cryptographic_suites_supported": ["ES256K"],
            "display": [
              {
                "name": "University Credential",
                "locale": "en-US",
                "logo": {
                  "url": "https://exampleuniversity.com/public/logo.png",
                  "alt_text": "a square logo of a university"
                },
                "background_color": "#12107c",
                "text_color": "#FFFFFF"
              }
            ],
            "credentialSubject": {
              "given_name": {
                "display": [
                  {"name": "Given Name", "locale": "en-US"}
                ]
              },
              "last_name": {
                "display": [
                  {"name": "Surname", "locale": "en-US"}
                ]
              },
              "degree": {},
              "gpa": {
                "display": [
                  {"name": "GPA"}
                ]
              }
            }
          }
        ]
      };
      var metadata = CredentialIssuerMetaData.fromJson(data);
      var metadata2 = CredentialIssuerMetaData.fromJson(metadata.toJson());

      expect(metadata.credentialsSupported.length,
          metadata2.credentialsSupported.length);
      expect(metadata.credentialsSupported.length, 1);
      expect(metadata.authorizationServer, metadata2.authorizationServer);
      expect(metadata.authorizationServer?.length, 1);
      expect(metadata.credentialEndpoint, metadata2.credentialEndpoint);
      expect(metadata.credentialIssuer, metadata2.credentialIssuer);
      expect(
          metadata.batchCredentialEndpoint, metadata2.batchCredentialEndpoint);
      expect(metadata.deferredCredentialEndpoint,
          metadata2.deferredCredentialEndpoint);
      expect(metadata.display?.length, metadata2.display?.length);
      expect(metadata.display?.length, 2);
    });

    test('draft 12, jwt vc json', () {
      var data = {
        "credential_issuer": "https://credential-issuer.example.com",
        "authorization_servers": ["https://server.example.com"],
        "credential_endpoint": "https://credential-issuer.example.com",
        "batch_credential_endpoint":
            "https://credential-issuer.example.com/batch_credential",
        "deferred_credential_endpoint":
            "https://credential-issuer.example.com/deferred_credential",
        "display": [
          {"name": "Example University", "locale": "en-US"},
          {"name": "Example Université", "locale": "fr-FR"}
        ],
        "credentials_supported": {
          "UniversityDegreeCredential": {
            "format": "jwt_vc_json",
            "scope": "UniversityDegree",
            "cryptographic_binding_methods_supported": ["did:example"],
            "cryptographic_suites_supported": ["ES256K"],
            "credential_definition": {
              "type": ["VerifiableCredential", "UniversityDegreeCredential"],
              "credentialSubject": {
                "given_name": {
                  "display": [
                    {"name": "Given Name", "locale": "en-US"}
                  ]
                },
                "family_name": {
                  "display": [
                    {"name": "Surname", "locale": "en-US"}
                  ]
                },
                "degree": {},
                "gpa": {
                  "display": [
                    {"name": "GPA"}
                  ]
                }
              }
            },
            "proof_types_supported": ["jwt"],
            "display": [
              {
                "name": "University Credential",
                "locale": "en-US",
                "logo": {
                  "url": "https://exampleuniversity.com/public/logo.png",
                  "alt_text": "a square logo of a university"
                },
                "background_color": "#12107c",
                "text_color": "#FFFFFF"
              }
            ]
          }
        }
      };
      var metadata = CredentialIssuerMetaData.fromJson(data);
      var metadata2 = CredentialIssuerMetaData.fromJson(metadata.toJson());

      expect(metadata.credentialsSupported.length,
          metadata2.credentialsSupported.length);
      expect(metadata.credentialsSupported.length, 1);
      expect(metadata.authorizationServer, metadata2.authorizationServer);
      expect(
          metadata.credentialsSupported['UniversityDegreeCredential']
              ?.proofTypesSupported?.length,
          1);
      print(metadata.credentialsSupported['UniversityDegreeCredential']
          ?.proofTypesSupported);
      expect(metadata.authorizationServer?.length, 1);
      expect(metadata.credentialEndpoint, metadata2.credentialEndpoint);
      expect(metadata.credentialIssuer, metadata2.credentialIssuer);
      expect(
          metadata.batchCredentialEndpoint, metadata2.batchCredentialEndpoint);
      expect(metadata.deferredCredentialEndpoint,
          metadata2.deferredCredentialEndpoint);
      expect(metadata.display?.length, metadata2.display?.length);
      expect(metadata.display?.length, 2);
    });
    test('draft 13, jwt vc json', () {
      var data = {
        "credential_issuer": "https://credential-issuer.example.com",
        "authorization_servers": ["https://server.example.com"],
        "credential_endpoint": "https://credential-issuer.example.com",
        "batch_credential_endpoint":
            "https://credential-issuer.example.com/batch_credential",
        "deferred_credential_endpoint":
            "https://credential-issuer.example.com/deferred_credential",
        "credential_response_encryption": {
          "alg_values_supported": ["ECDH-ES"],
          "enc_values_supported": ["A128GCM"],
          "encryption_required": false
        },
        "display": [
          {"name": "Example University", "locale": "en-US"},
          {"name": "Example Université", "locale": "fr-FR"}
        ],
        "credential_configurations_supported": {
          "UniversityDegreeCredential": {
            "format": "jwt_vc_json",
            "scope": "UniversityDegree",
            "cryptographic_binding_methods_supported": ["did:example"],
            "credential_signing_alg_values_supported": ["ES256"],
            "credential_definition": {
              "type": ["VerifiableCredential", "UniversityDegreeCredential"],
              "credentialSubject": {
                "given_name": {
                  "display": [
                    {"name": "Given Name", "locale": "en-US"}
                  ]
                },
                "family_name": {
                  "display": [
                    {"name": "Surname", "locale": "en-US"}
                  ]
                },
                "degree": {},
                "gpa": {
                  "display": [
                    {"name": "GPA"}
                  ]
                }
              }
            },
            "proof_types_supported": {
              "jwt": {
                "proof_signing_alg_values_supported": ["ES256"]
              }
            },
            "display": [
              {
                "name": "University Credential",
                "locale": "en-US",
                "logo": {
                  "url": "https://university.example.edu/public/logo.png",
                  "alt_text": "a square logo of a university"
                },
                "background_color": "#12107c",
                "text_color": "#FFFFFF"
              }
            ]
          }
        }
      };
      var metadata = CredentialIssuerMetaData.fromJson(data);
      var metadata2 = CredentialIssuerMetaData.fromJson(metadata.toJson());

      expect(metadata.credentialsSupported.length,
          metadata2.credentialsSupported.length);
      expect(metadata.credentialsSupported.length, 1);
      expect(metadata.authorizationServer, metadata2.authorizationServer);
      expect(metadata.authorizationServer?.length, 1);
      expect(metadata.credentialEndpoint, metadata2.credentialEndpoint);
      expect(metadata.credentialIssuer, metadata2.credentialIssuer);
      expect(
          metadata.batchCredentialEndpoint, metadata2.batchCredentialEndpoint);
      expect(metadata.deferredCredentialEndpoint,
          metadata2.deferredCredentialEndpoint);
      expect(metadata.display?.length, metadata2.display?.length);
      expect(metadata.display?.length, 2);
      expect(metadata.credentialResponseEncryptionRequired, isFalse);
      expect(metadata2.credentialResponseEncryptionRequired, isFalse);
      expect(metadata.credentialResponseEncryptionEncSupported,
          metadata2.credentialResponseEncryptionEncSupported);
      expect(metadata.credentialResponseEncryptionAlgSupported,
          metadata2.credentialResponseEncryptionAlgSupported);

      expect(
          metadata.credentialsSupported['UniversityDegreeCredential']
              ?.proofTypesSupported?.length,
          1);
      print(metadata.credentialsSupported['UniversityDegreeCredential']
          ?.proofTypesSupported);
    });

    test('draft 15, jwt vc json', () {
      var data = {
        "credential_issuer": "https://credential-issuer.example.com",
        "authorization_servers": ["https://server.example.com"],
        "credential_endpoint": "https://credential-issuer.example.com",
        "batch_credential_endpoint":
            "https://credential-issuer.example.com/batch_credential",
        "deferred_credential_endpoint":
            "https://credential-issuer.example.com/deferred_credential",
        "credential_response_encryption": {
          "alg_values_supported": ["ECDH-ES"],
          "enc_values_supported": ["A128GCM"],
          "encryption_required": false
        },
        "display": [
          {"name": "Example University", "locale": "en-US"},
          {"name": "Example Université", "locale": "fr-FR"}
        ],
        "credential_configurations_supported": {
          "UniversityDegreeCredential": {
            "format": "jwt_vc_json",
            "scope": "UniversityDegree",
            "cryptographic_binding_methods_supported": ["did:example"],
            "credential_signing_alg_values_supported": ["ES256"],
            "credential_definition": {
              "type": ["VerifiableCredential", "UniversityDegreeCredential"]
            },
            "claims": [
              {
                "path": ["credentialSubject", "given_name"],
                "display": [
                  {"name": "Given Name", "locale": "en-US"}
                ]
              },
              {
                "path": ["credentialSubject", "family_name"],
                "display": [
                  {"name": "Surname", "locale": "en-US"}
                ]
              },
              {
                "path": ["credentialSubject", "degree"]
              },
              {
                "path": ["credentialSubject", "gpa"],
                "mandatory": true,
                "display": [
                  {"name": "GPA"}
                ]
              }
            ],
            "proof_types_supported": {
              "jwt": {
                "proof_signing_alg_values_supported": ["ES256"],
                "key_attestations_required": {
                  "key_storage": ["iso_18045_moderate", "iso_18045_high"]
                }
              }
            },
            "display": [
              {
                "name": "University Credential",
                "locale": "en-US",
                "logo": {
                  "uri": "https://university.example.edu/public/logo.png",
                  "alt_text": "a square logo of a university"
                },
                "background_color": "#12107c",
                "text_color": "#FFFFFF"
              }
            ]
          }
        }
      };
      var metadata = CredentialIssuerMetaData.fromJson(data);
      //print(metadata);
      var metadata2 = CredentialIssuerMetaData.fromJson(metadata.toJson());

      expect(
          metadata.credentialsSupported['UniversityDegreeCredential']
              ?.claimDescriptions,
          isNotEmpty);
      expect(
          metadata.credentialsSupported['UniversityDegreeCredential']
              ?.proofTypesSupported?.length,
          1);
      print(metadata.credentialsSupported['UniversityDegreeCredential']
          ?.proofTypesSupported);
      print(metadata2.credentialsSupported['UniversityDegreeCredential']
          ?.proofTypesSupported);

      expect(metadata.credentialsSupported.length,
          metadata2.credentialsSupported.length);
      expect(metadata.credentialsSupported.length, 1);
      expect(metadata.authorizationServer, metadata2.authorizationServer);
      expect(metadata.authorizationServer?.length, 1);
      expect(metadata.credentialEndpoint, metadata2.credentialEndpoint);
      expect(metadata.credentialIssuer, metadata2.credentialIssuer);
      expect(
          metadata.batchCredentialEndpoint, metadata2.batchCredentialEndpoint);
      expect(metadata.deferredCredentialEndpoint,
          metadata2.deferredCredentialEndpoint);
      expect(metadata.display?.length, metadata2.display?.length);
      expect(metadata.display?.length, 2);
      expect(metadata.credentialResponseEncryptionRequired, isFalse);
      expect(metadata2.credentialResponseEncryptionRequired, isFalse);
      expect(metadata.credentialResponseEncryptionEncSupported,
          metadata2.credentialResponseEncryptionEncSupported);
      expect(metadata.credentialResponseEncryptionAlgSupported,
          metadata2.credentialResponseEncryptionAlgSupported);
    });

    test('V1, jwt_vc_json', () {
      var data = {
        "credential_issuer": "https://credential-issuer.example.com",
        "authorization_servers": ["https://server.example.com"],
        "credential_endpoint": "https://credential-issuer.example.com",
        "batch_credential_endpoint":
            "https://credential-issuer.example.com/batch_credential",
        "deferred_credential_endpoint":
            "https://credential-issuer.example.com/deferred_credential",
        "credential_response_encryption": {
          "alg_values_supported": ["ECDH-ES"],
          "enc_values_supported": ["A128GCM"],
          "encryption_required": false
        },
        "display": [
          {"name": "Example University", "locale": "en-US"},
          {"name": "Example Université", "locale": "fr-FR"}
        ],
        "credential_configurations_supported": {
          "UniversityDegreeCredential": {
            "format": "jwt_vc_json",
            "scope": "UniversityDegree",
            "cryptographic_binding_methods_supported": ["did:example"],
            "credential_signing_alg_values_supported": [-7],
            "credential_definition": {
              "type": ["VerifiableCredential", "UniversityDegreeCredential"]
            },
            "proof_types_supported": {
              "jwt": {
                "proof_signing_alg_values_supported": ["ES256"]
              }
            },
            "credential_metadata": {
              "claims": [
                {
                  "path": ["credentialSubject", "given_name"],
                  "display": [
                    {"name": "Given Name", "locale": "en-US"}
                  ]
                },
                {
                  "path": ["credentialSubject", "family_name"],
                  "display": [
                    {"name": "Surname", "locale": "en-US"}
                  ]
                },
                {
                  "path": ["credentialSubject", "degree"]
                },
                {
                  "path": ["credentialSubject", "gpa"],
                  "mandatory": true,
                  "display": [
                    {"name": "GPA"}
                  ]
                }
              ],
              "display": [
                {
                  "name": "University Credential",
                  "locale": "en-US",
                  "logo": {
                    "uri": "https://university.example.edu/public/logo.png",
                    "alt_text": "a square logo of a university"
                  },
                  "background_color": "#12107c",
                  "text_color": "#FFFFFF"
                }
              ]
            }
          }
        }
      };
      var metadata = CredentialIssuerMetaData.fromJson(data);
      print(metadata);
      var metadata2 = CredentialIssuerMetaData.fromJson(metadata.toJson());

      expect(
          metadata.credentialsSupported['UniversityDegreeCredential']
              ?.claimDescriptions,
          isNotEmpty);
      expect(
          metadata.credentialsSupported['UniversityDegreeCredential']
              ?.proofTypesSupported?.length,
          1);
      print(metadata.credentialsSupported['UniversityDegreeCredential']
          ?.proofTypesSupported);
      print(metadata2.credentialsSupported['UniversityDegreeCredential']
          ?.proofTypesSupported);

      expect(metadata.credentialsSupported.length,
          metadata2.credentialsSupported.length);
      expect(metadata.credentialsSupported.length, 1);
      expect(metadata.authorizationServer, metadata2.authorizationServer);
      expect(metadata.authorizationServer?.length, 1);
      expect(metadata.credentialEndpoint, metadata2.credentialEndpoint);
      expect(metadata.credentialIssuer, metadata2.credentialIssuer);
      expect(
          metadata.batchCredentialEndpoint, metadata2.batchCredentialEndpoint);
      expect(metadata.deferredCredentialEndpoint,
          metadata2.deferredCredentialEndpoint);
      expect(metadata.display?.length, metadata2.display?.length);
      expect(metadata.display?.length, 2);
      expect(metadata.credentialResponseEncryptionRequired, isFalse);
      expect(metadata2.credentialResponseEncryptionRequired, isFalse);
      expect(metadata.credentialResponseEncryptionEncSupported,
          metadata2.credentialResponseEncryptionEncSupported);
      expect(metadata.credentialResponseEncryptionAlgSupported,
          metadata2.credentialResponseEncryptionAlgSupported);
    });
  });

  group('credential request', () {
    test('draft 11', () {
      var data = {
        "format": "jwt_vc_json",
        "types": ["VerifiableCredential", "UniversityDegreeCredential"],
        "proof": {
          "proof_type": "jwt",
          "jwt":
              "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM"
        }
      };

      var request = OidCredentialRequest.fromJson(data);
      var request2 = OidCredentialRequest.fromJson(request.toJson());

      expect(request.credentialType, request2.credentialType);
      expect(request2.credentialType?.length, 2);
      expect(request.format, request2.format);

      var proof = request.proof?.first;
      var proof2 = request2.proof?.first;

      expect(proof?.proofType, 'jwt');
      expect(proof2?.proofType, 'jwt');
      expect(proof?.proofValue, proof2?.proofValue);
      expect(proof?.proofValue, isNotNull);
    });

    test('draft 12/1', () {
      var data = {
        "format": "mso_mdoc",
        "doctype": "org.iso.18013.5.1.mDL",
        "proof": {"proof_type": "cwt", "cwt": "..."}
      };

      var request = OidCredentialRequest.fromJson(data);
      var request2 = OidCredentialRequest.fromJson(request.toJson());

      expect(request.credentialType, request2.credentialType);
      expect(request.credentialType?.contains('org.iso.18013.5.1.mDL'), isTrue);
      expect(request2.credentialType?.length, 1);
      expect(request.format, request2.format);

      var proof = request.proof?.first;
      var proof2 = request2.proof?.first;

      expect(proof?.proofType, 'cwt');
      expect(proof2?.proofType, 'cwt');
      expect(proof?.proofValue, proof2?.proofValue);
      expect(proof?.proofValue, isNotNull);
    });
    test('draft 12/2', () {
      var data = {
        "credential_identifier": "CivilEngineeringDegree-2023",
        "proof": {
          "proof_type": "jwt",
          "jwt":
              "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE1MzY5NTk5NTksIm5vbmNlIjoidFppZ25zbkZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM"
        }
      };

      var request = OidCredentialRequest.fromJson(data);
      var request2 = OidCredentialRequest.fromJson(request.toJson());

      expect(request.credentialIdentifier, request2.credentialIdentifier);
      expect(request2.credentialIdentifier, 'CivilEngineeringDegree-2023');
      expect(request.format, request2.format);

      var proof = request.proof?.first;
      var proof2 = request2.proof?.first;

      expect(proof?.proofType, 'jwt');
      expect(proof2?.proofType, 'jwt');
      expect(proof?.proofValue, proof2?.proofValue);
      expect(proof?.proofValue, isNotNull);
    });

    test('draft 15', () {
      var data = {
        "credential_configuration_id": "org.iso.18013.5.1.mDL",
        "proof": {
          "proof_type": "jwt",
          "jwt":
              "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ"
        }
      };

      var request = OidCredentialRequest.fromJson(data);
      var request2 = OidCredentialRequest.fromJson(request.toJson());

      expect(request.credentialConfigurationId,
          request2.credentialConfigurationId);
      expect(request2.credentialConfigurationId, 'org.iso.18013.5.1.mDL');

      var proof = request.proof?.first;
      var proof2 = request2.proof?.first;

      expect(proof?.proofType, 'jwt');
      expect(proof2?.proofType, 'jwt');
      expect(proof?.proofValue, proof2?.proofValue);
      expect(proof?.proofValue, isNotNull);
    });
  });

  group('credential response', () {
    test('draft 11 normal', () {
      var data = {
        "format": "jwt_vc_json",
        "credential": "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L",
        "c_nonce": "fGFF7UkhLa",
        "c_nonce_expires_in": 86400
      };

      var response = OidCredentialResponse.fromJson(data);
      var response2 = OidCredentialResponse.fromJson(response.toJson());
      print(response);

      expect(response.format, response2.format);
      expect(response.credential, response2.credential);
      expect(response.cNonceExpiresIn, response2.cNonceExpiresIn);
      expect(response.cNonce, response2.cNonce);
    });

    test('draft 11 deferred', () {
      var data = {
        "acceptance_token": "8xLOxBtZp8",
        "c_nonce": "wlbQc6pCJp",
        "c_nonce_expires_in": 86400
      };

      var response = OidCredentialResponse.fromJson(data);
      var response2 = OidCredentialResponse.fromJson(response.toJson());
      print(response);

      expect(response.transactionId, response2.transactionId);
      expect(response.cNonceExpiresIn, response2.cNonceExpiresIn);
      expect(response.cNonce, response2.cNonce);
    });

    test('draft 12 deferred', () {
      var data = {
        "transaction_id": "8xLOxBtZp8",
        "c_nonce": "wlbQc6pCJp",
        "c_nonce_expires_in": 86400
      };

      var response = OidCredentialResponse.fromJson(data);
      var response2 = OidCredentialResponse.fromJson(response.toJson());
      print(response);

      expect(response.transactionId, response2.transactionId);
      expect(response.cNonceExpiresIn, response2.cNonceExpiresIn);
      expect(response.cNonce, response2.cNonce);
    });

    test('draft 14 normal', () {
      var data = {
        "credentials": [
          "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L",
          "YXNkZnNhZGZkamZqZGFza23....29tZTIzMjMyMzIzMjMy"
        ],
        "c_nonce": "fGFF7UkhLa",
        "c_nonce_expires_in": 86400
      };

      var response = OidCredentialResponse.fromJson(data);
      var response2 = OidCredentialResponse.fromJson(response.toJson());
      print(response);

      expect(response.credentials?.length, response2.credentials?.length);
      expect(response.credentials?.length, 2);
      expect(response2.cNonce, response.cNonce);
      expect(response.cNonce, 'fGFF7UkhLa');
    });

    test('draft 15 normal', () {
      var data = {
        "credentials": [
          {"credential": "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L"},
          {"credential": "YXNkZnNhZGZkamZqZGFza23....29tZTIzMjMyMzIzMjMy"}
        ],
        "notification_id": "3fwe98js"
      };

      var response = OidCredentialResponse.fromJson(data);
      var response2 = OidCredentialResponse.fromJson(response.toJson());
      print(response);

      expect(response.credentials?.length, response2.credentials?.length);
      expect(response.credentials?.length, 2);
      expect(response2.notificationId, response.notificationId);
      expect(response.notificationId, '3fwe98js');
    });
  });
}
