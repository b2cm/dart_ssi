import 'package:dart_ssi/didcomm.dart';
import 'package:dart_ssi/exceptions.dart';
import 'package:dart_ssi/util.dart';

class DidcommProposeCredentialMessageHandler
    extends AbstractDidcommMessageHandler {
  @override
  List<String> get supportedTypes => [DidcommMessages.proposeCredential.value];

  @override
  bool get needsConnectionDid => false;

  @override
  bool get needsCredentialDid => false;

  @override
  bool get needsReplyTo => true;

  @override
  bool get needsWallet => true;

  @override
  Future<OfferCredential?> handle(DidcommMessage message) async {
    var plainTextMessage = message as DidcommPlaintextMessage;

    var propose = ProposeCredential.fromJson(message.toJson());

    // it is expected that the wallet changes the did,
    // the credential should be issued to
    var vcSubjectId = propose.detail!.first.credential.credentialSubject['id'];

    for (var ea in enumerate(propose.attachments!)) {
      var i = ea.index;
      var a = ea.value!;
      // to check, if the wallet controls the did the holder is expected
      // to sign the attachment
      try {
        if (!(await a.data.verifyJws(vcSubjectId))) {
          throw DidcommServiceException(
              "Could not verify the JWS at index $i because the "
              "signature is invalid",
              code: 9308490238);
        }
      } on Exception catch (e) {
        throw DidcommServiceException(
            "The attachment at index $i is not "
            "verifiable due to `{${e.toString()}`",
            baseException: e,
            code: 4823482309);
      }
    }

    // answer with offer credential message
    var offer = OfferCredential(
        threadId: propose.threadId ?? message.id,
        detail: propose.detail,
        from: connectionDid ?? getConversationDid(message, wallet!),
        to: [propose.from!],
        replyTo: replyTo);

    return offer;
  }
}
