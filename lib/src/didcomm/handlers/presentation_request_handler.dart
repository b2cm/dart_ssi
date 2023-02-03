import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/didcomm.dart';
import 'package:dart_ssi/util.dart';

class DidcommPresentationRequestMessageHandler extends AbstractDidcommMessageHandler {

  @override
  List<String> get supportedTypes => [
    DidcommMessages.requestPresentation.value
  ];

  @override
  bool get needsConnectionDid => false;
  @override
  bool get needsCredentialDid => false;
  @override
  bool get needsReplyTo => true;
  @override
  bool get needsWallet => true;

  @override
  Future<Presentation> handle(DidcommMessage message) async {

    var requestPresentation = RequestPresentation.fromJson(message.toJson());

    var res = await searchForMatchingCredentials(
        message: requestPresentation,
        wallet: wallet!,
    );

    var allCredentialFlattened =
      res.fold(<VerifiableCredential>[],
          (List<VerifiableCredential> l, FilterResult e) =>
            l..addAll(e.credentials));

    List<FilterResult> finalSend = [];
    for (var result in res) {
      finalSend.add(FilterResult(
          credentials: allCredentialFlattened,
          matchingDescriptorIds: result.matchingDescriptorIds,
          presentationDefinitionId: result.presentationDefinitionId,
          submissionRequirement: result.submissionRequirement));
    }

    var vp = await buildPresentation(finalSend, wallet!,
        requestPresentation.presentationDefinition.first.challenge);

    var presentationMessage = Presentation(
        to: [requestPresentation.from!],
        replyTo: replyTo,
        verifiablePresentation: [VerifiablePresentation.fromJson(vp)],
        threadId: requestPresentation.threadId ?? requestPresentation.id);

    return presentationMessage;
  }
}
