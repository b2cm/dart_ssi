import 'package:dart_ssi/didcomm.dart';

class DidcommOfferCredentialMessageHandler extends AbstractDidcommMessageHandler {

  @override
  List<String> get supportedTypes => [
    DidcommMessages.offerCredential.value
  ];

  bool get needsConnectionDid => false;
  bool get needsCredentialDid => false;
  bool get needsReplyTo => true;
  bool get needsWallet => true;

  @override
  Future<RequestCredential> handle(DidcommMessage message) async {
    var offer = OfferCredential.fromJson(message.toJson());

    var request = generateRequestCredentialMessageFromOffer(
        offer: offer,
        wallet: wallet!,
        replyTo: replyTo!);

    return request;
  }
}