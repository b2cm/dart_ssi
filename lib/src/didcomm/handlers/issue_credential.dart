import 'package:dart_ssi/didcomm.dart';
import 'package:dart_ssi/exceptions.dart';
import 'package:dart_ssi/wallet.dart';

/// Will store the credential inside the handler
class DidcommIssueCredentialHandler extends AbstractDidcommMessageHandler {
  @override
  List<String> get supportedTypes => [DidcommMessages.issueCredential];

  @override
  bool get needsConnectionDid => false;
  @override
  bool get needsCredentialDid => false;
  @override
  bool get needsReplyTo => false;
  @override
  bool get needsWallet => true;

  @override
  Future<IssueCredential?> handle(DidcommMessage message) async {
    // message as DidcommPlaintextMessage;

    var request = IssueCredential.fromJson(message.toJson());
    // var request = message as IssueCredential;
    Connection? myConnection;

    for (var entry in wallet!.getAllConnections().entries) {
      var did = entry.key;
      var connection = entry.value;
      if (request.to!.contains(did)) {
        myConnection = connection;
        break;
      }
    }

    if (myConnection == null) {
      throw DidcommServiceException(
          "This wallet is not owner of any "
          "of receivers of this credential (${request.to!.join(", ")}).",
          code: 34983459);
    }

    String oldCredentialDid = request.credentials!.first.id ??
        request.credentials!.first.credentialSubject['id'];
    Credential? oldCred = wallet!.getCredential(oldCredentialDid);

    if (oldCred == null) {
      throw DidcommServiceException(
          "This wallet doesn't contain a credential "
          "entry with did $oldCredentialDid. Please create one beforehand.",
          code: 9583904);
    }

    // Credential should be empty.
    if (oldCred.w3cCredential != '' && !force) {
      throw DidcommServiceException(
          "A credential is already stored. Use force "
          "to overwrite it.",
          code: 9583904);
    }

    // This searches each key type for a resolvable hdPath
    // @Todo the keytype should be determined by the credentials' key
    KeyType? successFullKeyType;
    for (var kt in KeyType.values) {
      try {
        await wallet!.storeCredential(
            request.credentials!.first.toString(), '', oldCred.hdPath,
            keyType: KeyType.secp256k1);
        successFullKeyType = kt;
        break;
      } catch (e) {
        // ignore, this is a one-off ()
      }
    }

    if (successFullKeyType == null) {
      throw DidcommServiceException(
          "Could not store credential. "
          " I cannot find a matching key type",
          code: 4827389234);
    }

    return null;
  }
}
