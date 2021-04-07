# flutter_ssi_wallet

Dart Package for SSI Wallet. This Package contains classes and functions for storing verifiable credentials
and relating key-pairs; issue, verify and revoke credentials and presentations and interact with a erc1056 smartContract.

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
Most important part of this package are the credentials supported by it. These credentials are able to support selective disclosure.
Therefor every attribute of a credential is hashed with a salt and the verifiable credential signed by the issuer
only contains the hashes. In the wallet of the holder both credentials - the one containing all disclosed values 
with hashes and salts and the signed one - are stored. E.g. the first mentioned type - in the package referred to to as plaintext-credential -
looks like this:
```
{
   "id":"did:ethr:0x1611994c317bed3102D65A93B667Dbe0591Da41c",
   "name": {
   "value":"Max",
   "salt":"dc0931a0-60c6-4bc8-a27d-b3fd13e62c63",
   "hash":"0xd8925653ed000200d2b491bcabe2ea69f378abb91f056993a6d3e3b28ad4ccc4"
  },
  "age": {
   "value":20,
   "salt":"3e9bacd3-aa74-42c1-9895-e490e3931a73",
  "hash":"0x43bde6fcd11015c6a996206dadd25e149d131c69a7249280bae723c6bad53888"
  }
}
```

and the corresponding signed verifiable credential like this:
```
{
    "@context":["https://www.w3.org/2018/credentials/v1",
    "https://identity.hs-mittweida.de/credentials/ld-context/"],
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
For now the only supported signature-suite for the proof-section is [EcdsaSecp256k1RecoverySignature2020](https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/).

## Usage of Credentials
As the [W3C-Specification for Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) describes, a credential is issued by an issuer, stored by a holder and presented to verifier. 
How to achieve this using this package is shown in the examples [issuance.dart](http://suc-1.hs-mittweida.de/startervorhaben-3/flutter_ssi_wallet/-/blob/master/examples/issuance.dart) 
and [verification.dart](http://suc-1.hs-mittweida.de/startervorhaben-3/flutter_ssi_wallet/-/blob/master/examples/verification.dart). Beside this a credential could be revoked by its issuer
as shown in [credentialRevocation.dart](http://suc-1.hs-mittweida.de/startervorhaben-3/flutter_ssi_wallet/-/blob/master/examples/credentialRevocation.dart). 
For the revocation a simple Ethereum-SmartContract is used, that should be deployed for each issuer.

## Key- and Identifier Management
The identifiers used here are [decentralized identifiers (DID)](https://www.w3.org/TR/did-core/) according to a [ethereum-specific DID-Method](https://github.com/decentralized-identity/ethr-did-resolver). These DIDs are ethereum-addresses prepended with `did:ethr`.
Because of this a secp256k1- key pair belongs to each identifier. The keys are managed in a hierarchical-deterministic manner as known from Bitcoin wallets, because it is recommended to use
a new identifier for each credential or service you would like to interact with. To generate one use
```
var newDID = await wallet.getNextCredentialDID();
// or (when get in contact with a new service)
var newDID = await wallet.getNextConnectionDID();
```
This package only supports credentials that are issued to different dids each, because each credential is identified be it.

With the [ERC1056-SmartContract (EtheremDIDRegistry)](https://eips.ethereum.org/EIPS/eip-1056) it is for
example possible to rotate a key if it is lost/corrupted. An example for that could be found in [keyRotation.dart](http://suc-1.hs-mittweida.de/startervorhaben-3/flutter_ssi_wallet/-/blob/master/examples/keyRotation.dart).  

The identifier could not only be used to bind credentials on it. They could also be used as an replacement for an 'normal' username. These are referred to as ConnectionDIDs in this package.
A usage example for this could be found in [registration.dart](http://suc-1.hs-mittweida.de/startervorhaben-3/flutter_ssi_wallet/-/blob/master/examples/registration.dart). Therefor a
registration process for a new user wthin an online-service could include the following steps:   

1. User generates new Connection DID and submits this to service. That's enough to authenticate an user technically, when he/she returns (using digital signatures).
2. To identify an user (Who is the person behind the identifier?) credentials are needed and submitted.
