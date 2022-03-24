import 'package:uuid/uuid.dart';

import '../../dids/did_document.dart';
import '../didcomm_jwm.dart';

class DidExchangeRequest extends DidcommPlaintextMessage {
  String? label;
  String? goalCode;
  String? goal;
  late String did;
  DidDocument? didDocument;

  DidExchangeRequest(
      {String? id,
      required String parentThreadId,
      String? threadId,
      this.label,
      this.goal,
      this.goalCode,
      this.didDocument,
      required this.did})
      : super(
            id: id ?? Uuid().v4(),
            type: 'https://didcomm.org/didexchange/2.0/request',
            body: {},
            threadId: threadId,
            parentThreadId: parentThreadId) {
    body['did'] = did;
    if (label != null) body['label'] = label;
    if (goalCode != null) body['goal_code'] = goalCode;
    if (goal != null) body['goal'] = goal;
    if (didDocument != null) {
      attachments = [
        Attachment(
            data: AttachmentData(json: didDocument!.toJson()),
            id: Uuid().v4(),
            mediaType: 'application/json')
      ];
    }
  }

  DidExchangeRequest.fromJson(dynamic jsonObject) : super.fromJson(jsonObject) {
    if (type != 'https://didcomm.org/didexchange/2.0/request')
      throw Exception('Wrong type');
    if (parentThreadId == null) throw Exception('Parent thread id needed');
    label = body['label'];
    goalCode = body['goal_code'];
    goal = body['goal'];
    if (body.containsKey('did'))
      did = body['did'];
    else
      throw Exception('did property is needed in didExchangeRequest');
    if (attachments != null && attachments!.length > 0) {
      attachments![0].data.resolveData();
      didDocument = DidDocument.fromJson(attachments![0].data.json!);
    }
  }
}

class DidExchangeResponse extends DidcommPlaintextMessage {
  late String did;
  DidDocument? didDocument;

  DidExchangeResponse(
      {String? id,
      required String threadId,
      required this.did,
      this.didDocument})
      : super(
            id: id ?? Uuid().v4(),
            type: 'https://didcomm.org/didexchange/2.0/response',
            body: {}) {
    body['did'] = did;
    if (didDocument != null) {
      attachments = [
        Attachment(
            data: AttachmentData(json: didDocument!.toJson()),
            id: Uuid().v4(),
            mediaType: 'application/json')
      ];
    }
  }

  DidExchangeResponse.fromJson(dynamic jsonObject)
      : super.fromJson(jsonObject) {
    if (type != 'https://didcomm.org/didexchange/2.0/response')
      throw Exception('Wrong type');
    if (threadId == null) throw Exception('thread id needed');
    if (body.containsKey('did'))
      did = body['did'];
    else
      throw Exception('did property is needed in didExchangeRequest');
    if (attachments != null && attachments!.length > 0) {
      attachments![0].data.resolveData();
      didDocument = DidDocument.fromJson(attachments![0].data.json!);
    }
  }
}
