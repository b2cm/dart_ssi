## 3.1.0
- add P-256, P-384 and P-521 as possible keytypes to wallet implementation
- add JsonWebSignature2020 for Credential signing
- bugfixes

## 3.0.1
- change dependency: json_schema2 => json_schema

## 3.0.0
- **Breaking change** in the function searchCredentialsForPresentationDefintion: No longer throws Exception, when there are not enough matching credentials in Wallet but uses fulfillable-property of FilterResult to indicate, that an inputDescriptor or submissionRequirement cant be fulfilled
- add Functions to check typ of DidcommMessage (Plaintext, Signed or Encrypted; based on JsonSchema)
- restructuring for better web compatibility
- update json_schema2 version
- bugfixes

## 2.1.0
- add experimental implementation of openid4VC/VP
- add more keytypes for did:key resolution
- small API-Change for signStringOrJson / VerifyStringSignature : use named parameters
- bugfixes

## 2.0.1
- Bugfixes

## 2.0.0
- **Breaking Change**: when using links in didcomm-attachments, checking the hash is now performed
- add CredentialStatusList2021 for revocation
- small improvements in verification and signing VP and VC

## 1.0.6
- add CredentialStatusList2020 for revocation
- add resolution of did:web
- some example handlers for didcomm-messages
- bugfixes and improvements

## 1.0.5
- bugfixes and improvements

## 1.0.4
- bugfixes (in: filtering credentials according to a presentation definition; the wallet, didcomm message attachments; please-ack header)
- function to build presentation Definition for a credential (to e.g. propose it for presentation)

## 1.0.3
- add function to build x509 certificate signing request for did
- update readme.md

## 1.0.2
- small bug-fixes
- prepare for publishing (actual linting, etc.)

## 1.0.1
- dependency updates
- change from dart_web3 to web3dart
- bugfix

## 1.0.0
- **Breaking Change**: all Signatures are now correct JSON-LD Signature because JSON-LD Processor is ready to use
- fix little wallet bug (wallet was cleared when password was wrong)

## 0.3.4
- add support for credential manifest
- Update README.md (Links to further examples)

## 0.3.3
- bugfixes
- add web_redirect header

## 0.3.2
- bugfixes and improvements
- update dev-dependencies

## 0.3.1
- extensible API for credential/presentation signing and verification
- Discover Feature protocol: new feature-type `attachment-format`
- Out-of-Band messages: attachment are no required anymore (but optional)

## 0.3.0
- new type name for empty messages
- add support for discover feature protocol

## 0.2.0
- change response_to header of plaintext messages to reply_url and reply_to (conformance to jwm spec)

## 0.1.2
- check signature of didcomm message attachments
- resolve didcomm message attachment from given link

## 0.1.1
- support storing didcomm messages in wallet

## 0.1.0
- add support for didcomm v2
- support did:key
- support Ed25519Signature2020 Signature Suite

## 0.0.1
- Initial release
    - Support did:ethr
    - Sign/Verify Credentials and Presentation (EcdsaSecp256k1RecoverySignature2020)
    - hash based selective disclosure mechanism
    - Support IWCE
    - Simple Ethereum based Credential Revocation
