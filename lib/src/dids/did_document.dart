import '../credentials/credential_operations.dart';
import '../util/types.dart';

class DidDocument implements JsonObject {
  DidDocument.fromJson(dynamic jsonObject) {
    var document = credentialToMap(jsonObject);
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    return jsonObject;
  }
}
