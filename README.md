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
