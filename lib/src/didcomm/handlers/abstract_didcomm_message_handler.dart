import 'package:dart_ssi/didcomm.dart';
import 'package:dart_ssi/exceptions.dart';
import 'package:dart_ssi/wallet.dart';

import 'invitation_handler.dart';
import 'issue_credential.dart';

/// Abstract class for handling DidComm messages
abstract class AbstractDidcommMessageHandler {
  String? connectionDid;
  String? credentialDid;
  List<String>? replyTo;
  WalletStore? wallet;

  Map<String, dynamic> extraParams = {};

  List<String> get supportedTypes;

  bool get needsConnectionDid;
  bool get needsCredentialDid;
  bool get needsReplyTo;
  bool get needsWallet;

  // Force a operation on doubt
  bool get force =>
      extraParams.containsKey('force') && extraParams['force'] == true;

  AbstractDidcommMessageHandler();
  Future<DidcommMessage?> execute(DidcommMessage message) {
    var plainTextMessage = message as DidcommPlaintextMessage;
    if (needsConnectionDid && connectionDid == null) {
      throw DidcommServiceException(
          "Handler for ${plainTextMessage.type}  needs a connection did.",
          code: 3249823);
    }
    if (needsCredentialDid && credentialDid == null) {
      throw DidcommServiceException(
          "Handler for ${plainTextMessage.type} needs a credential did.",
          code: 23498239402);
    }
    if (needsWallet && wallet == null) {
      throw DidcommServiceException(
          "Handler for ${plainTextMessage.type} needs a wallet.",
          code: 823490835);
    }

    if (needsReplyTo && (replyTo == null || replyTo!.isEmpty)) {
      throw DidcommServiceException(
          "Handler for ${plainTextMessage.type} needs a replyTo.",
          code: 9583490);
    }

    if (!supportedTypes.contains(plainTextMessage.type)) {
      throw DidcommServiceException(
          "Handler cannot handle ${plainTextMessage.type} messages.",
          code: 234238920);
    }

    return handle(message);
  }

  /// Actual handling method.
  /// variables can be expected to be non-null as configured
  Future<DidcommMessage?> handle(DidcommMessage message);
}

var ALL_HANDLERS = [
  DidcommInvitationMessageHandler(),
  DidcommProposeCredentialMessageHandler(),
  DidcommRequestCredentialMessageHandler(),
  DidcommOfferCredentialMessageHandler(),
  DidcommPresentationRequestMessageHandler(),
  DidcommIssueCredentialHandler(),
];
