import 'package:dart_ssi/didcomm.dart';

class DidcommOfferCredentialMessageHandler extends AbstractDidcommMessageHandler {

  @override
  List<String> get supportedTypes => [
    DidcommMessages.offerCredential.value
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
  Future<RequestCredential> handle(DidcommMessage message) async {
    var offer = OfferCredential.fromJson(message.toJson());

    var request = generateRequestCredentialMessageFromOffer(
        offer: offer,
        wallet: wallet!,
        replyTo: replyTo!);

    return request;
  }
}