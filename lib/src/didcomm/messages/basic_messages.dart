import 'package:uuid/uuid.dart';

import '../didcomm_jwm.dart';

class EmptyMessage extends DidcommPlaintextMessage {
  EmptyMessage({String? id})
      : super(
            id: id ?? Uuid().v4(),
            type: 'https://didcomm.org/reserved/2.0/empty',
            body: {});

  EmptyMessage.fromJson(dynamic jsonObject) : super.fromJson(jsonObject) {
    if (type != 'https://didcomm.org/reserved/2.0/empty')
      throw Exception('Wrong message type');
    if (body.length > 0) throw Exception('this message is not empty');
  }
}
