# Extending Credential signing
To implement your own signature suite for signing and verifying credentials, build a signer-class extending `Signer`
and implement the containing methods. The class itself and sample implementations cold be found in 
[credentials/credential_signer.dart](https://github.com/b2cm/dart_ssi/blob/didcomm/credentials/credential_signer.dart).

## buildProof - Method
- the parameter `data` is the data, that should be signed. It is expected, that your method could work with the following datatypes:
  - `List<int>` representing hashed data
  - `String` 
  - `Map<String, dynamic>` representing a json-Object
- the method should return a proof-object (json object = `Map<String, dynamic>`) according to [Linked Data Proof data model](https://w3c-ccg.github.io/data-integrity-spec/)

## verify - Method
- for `data` parameter there are same expectations as in `buildProof`-method. This is the data that was signed without its `proof` section.

## use your signers
- the credential and presentation signing functions (`signCredential` and `buildPresentation`) allows you to give them your signer as parameter. Then this own is used exclusively. Per default one of the implemented signers is selected according zo the did the credential/presentation should be signed with.
- the credential and presentation verification function (`verifyCredential` and `verifyPresentation`) expect a function that could select a signer according to the signature type as optional parameter. This function should expect the signature type (`String`) as parameter and return a Signer-Object. 