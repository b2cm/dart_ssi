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
