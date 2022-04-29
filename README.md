# dart_ssi
Dart Package supporting several standards in SSI space, inclusive a minimal wallet implementation based on [Hive](https://docs.hivedb.dev/#/). 
This Package contains classes and functions for storing verifiable credentials
and relating key-pairs; issue, verify and revoke credentials and presentations and interact with a erc1056 smartContract.
Additional two exchange protocols ([IWCE](https://b2cm.github.io/iwce/) and 
[DIDComm V2](https://identity.foundation/didcomm-messaging/spec/)) for verifiable Credentials and Presentations are supported.

**Important Note**: This package is work-in-progress. The API is subject to change and the code was not tested extensively.

## API Documentation
To get a complete documentation of the API of this library use [`dart doc`](https://dart.dev/tools/dart-doc).

## Getting Started

To setup a Wallet just do this:
```
void main() {
  var wallet = new WalletStore('holder');
  await wallet.openBoxes('holderPW');
  wallet.initialize();
}
```

## Credentials

Most important part of this package are the credentials supported by it. These credentials are able to support selective disclosure 
using a simple hash-based mechanism.
Therefore every attribute of a credential is hashed with a salt. The verifiable credential signed by the issuer
only contains the hashes. In the wallet of the holder both credentials - the one containing all values 
with their salts and the signed one - are stored. 
E.g. the first mentioned type - in the package referred to to as plaintext-credential -
looks like this:
```
{
   "id":"did:ethr:0x1611994c317bed3102D65A93B667Dbe0591Da41c",
   "type": ["HashedPlaintextCredential2021","NameAgeCredential"],
   "hashAlg": "keccak-256",
   "name": {
   "value":"Max",
   "salt":"dc0931a0-60c6-4bc8-a27d-b3fd13e62c63",
  },
  "age": {
   "value":20,
   "salt":"3e9bacd3-aa74-42c1-9895-e490e3931a73",
  }
}
```

and the corresponding signed verifiable credential like this:
```
{
    "@context":["https://www.w3.org/2018/credentials/v1",
    "https://credentials.hs-mittweida.de/credentials/ld-context/"],
    "type":["VerifiableCredential"],
    "credentialSubject": {
        "id":"did:ethr:0x1611994c317bed3102D65A93B667Dbe0591Da41c",
        "type":"NameAgeCredential",
        "name":"0xd8925653ed000200d2b491bcabe2ea69f378abb91f056993a6d3e3b28ad4ccc4",
        "age":"0x43bde6fcd11015c6a996206dadd25e149d131c69a7249280bae723c6bad53888"},
    "issuer":"did:ethr:0x6d32738382c6389eF0D79045a76411C42Fff3a5e",
    "issuanceDate":"2020-11-30T11:06:39.423520Z",
    "proof": {
        "type":"EcdsaSecp256k1RecoverySignature2020",
        "proofPurpose":"assertionMethod",
        "verificationMethod":"did:ethr:0x6d32738382c6389eF0D79045a76411C42Fff3a5e",
        "created":"2020-11-30T11:06:39.497073Z",
        "jws":"ey..E="}
}
```
For now the only supported signature-suites for the proof-section are
[EcdsaSecp256k1RecoverySignature2020](https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/) and 
[Ed25519Signature2020](https://w3c-ccg.github.io/lds-ed25519-2020/).

## Usage of Credentials
As the [W3C-Specification for Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) describes, a credential is issued by an issuer, stored by a holder and presented to verifier. 
How to achieve this using this package is shown in the examples [issuance.dart](http://suc-1.hs-mittweida.de/startervorhaben-3/dart_ssi/-/blob/master/examples/issuance.dart) 
and [verification.dart](https://github.com/b2cm/dart_ssi/blob/didcomm/examples/verification.dart). Beside this a credential could be revoked by its issuer
as shown in [credentialRevocation.dart](https://github.com/b2cm/dart_ssi/blob/didcomm/examples/credentialRevocation.dart). 
For the revocation a simple Ethereum-SmartContract is used, that should be deployed for each issuer.

## Key- and Identifier Management
The identifiers used here are [decentralized identifiers (DID)](https://www.w3.org/TR/did-core/) 
according to [did:ethr Method](https://github.com/decentralized-identity/ethr-did-resolver) and [did:key Method](https://w3c-ccg.github.io/did-method-key/).
In case of the later one, only Ed2219 and X2555 keys are supported now.
All keys are managed in a hierarchical-deterministic manner as known from Bitcoin wallets, because it is recommended to use
a new identifier for each credential or service you would like to interact with. To generate one use
```
var newDID = await wallet.getNextCredentialDID();
// or (when get in contact with a new service)
var newDID = await wallet.getNextConnectionDID();
```
This package only supports credentials that are issued to different dids each, because each credential is identified be it.

With the [ERC1056-SmartContract (EthereumDIDRegistry)](https://eips.ethereum.org/EIPS/eip-1056) it is for
example possible to rotate a key if it is lost/corrupted.
An example for that could be found in [keyRotation.dart](http://suc-1.hs-mittweida.de/startervorhaben-3/dart_ssi/-/blob/master/examples/keyRotation.dart).  

An identifier could not only be used to bind credentials on it. 
They could also be used to encrypt/sign didcomm messages with or as an replacement for an 'normal' username. 
These are referred to as ConnectionDIDs in this package.
A usage example for the second case could be found in 
[registration.dart](https://github.com/b2cm/dart_ssi/blob/didcomm/examples/registration.dart). 
Therefore a
registration process for a new user within an online-service could include the following steps:   

1. User generates new Connection DID and submits this to service. That's enough to authenticate an user technically, when he/she returns (using digital signatures).
2. To identify an user (Who is the person behind the identifier?) credentials are needed and submitted.

## Didcomm
This package supports the [Didcomm V2 message format](https://identity.foundation/didcomm-messaging/spec/). Except of the optional XChacha20Poly1305 Encryption all Encryption, Key Agreement, Key Wrap and signing
Algorithms mentioned in the spec are supported.
From a message level perspective the following Message/Protocols are supported:
- [Empty Message](https://identity.foundation/didcomm-messaging/spec/#the-empty-message)
- [Problem Report](https://identity.foundation/didcomm-messaging/spec/#problem-reports)
- [Out-Of-Band Message](https://identity.foundation/didcomm-messaging/spec/#out-of-band-messages)
- [issue-credential V3](https://github.com/decentralized-identity/waci-presentation-exchange/tree/main/issue_credential) with [JSON-LD Credential Attachment](https://github.com/hyperledger/aries-rfcs/tree/main/features/0593-json-ld-cred-attach)
- [present-proof V3](https://github.com/decentralized-identity/waci-presentation-exchange/blob/main/present_proof/present-proof-v3.md) with [DIF Presentation Exchange Attachment](https://github.com/hyperledger/aries-rfcs/tree/main/features/0510-dif-pres-exch-attach) and the slightly change that this packages uses [V2 of presentation exchanges](https://identity.foundation/presentation-exchange/) and tries to support all features of it and not only the listed ones in the definition of the attachment format.


A full example for issuing a credential and requesting a presentation using didcomm can be found in [didcomm.dart](https://github.com/b2cm/dart_ssi/blob/didcomm/examples/didcomm.dart) 

## TODOs/Future Plans
- because of a missing json-ld processing api for dart all generated signature are not fully correct json-ld signatures. Therefore the plan for the near future is to develop an json-ld processor to get interoperable json-ld signatures.
- support of [didcomm routing messages](https://identity.foundation/didcomm-messaging/spec/#routing)
- `from_prior` header is not fully supported now
- the hash in attachment data of a didcomm message is not checked yet 
- not all features of Presentation Exchange are evaluated correctly now. These are:
    - `path_nested` property in `submission_requirement`
    - `is_holder` property
    - `same_subject` property
    - `statuses` property
    - `predicate` property
- there are not many tests 
    


