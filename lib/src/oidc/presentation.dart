import 'dart:convert';

import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/src/util/types.dart';
import 'package:dart_ssi/src/util/utils.dart';

class RequestObject implements JsonObject {
  String? responseType;
  String? clientId;
  String? responseMode;
  String? redirectUri;
  String? nonce;
  PresentationDefinition? presentationDefinition;
  String? presentationDefinitionUri;

  RequestObject(
      {this.clientId,
      this.nonce,
      this.redirectUri,
      this.responseMode,
      this.responseType,
      this.presentationDefinition});

  RequestObject.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);

    responseType = jsonObject['response_type'];
    clientId = jsonObject['client_id'];
    responseMode = jsonObject['response_mode'];
    redirectUri = jsonObject['redirect_uri'];
    nonce = jsonObject['nonce'];
    presentationDefinitionUri = jsonObject['presentation_definition_uri'];

    if (jsonObject.containsKey('presentation_definition')) {
      presentationDefinition = PresentationDefinition.fromJson(
          jsonObject['presentation_definition']);
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (clientId != null) {
      jsonObject['client_id'] = clientId;
    }
    if (responseType != null) {
      jsonObject['response_type'] = responseType;
    }
    if (responseMode != null) {
      jsonObject['response_mode'] = responseMode;
    }

    if (redirectUri != null) {
      jsonObject['redirect_uri'] = redirectUri;
    }
    if (nonce != null) {
      jsonObject['nonce'] = nonce;
    }
    if (presentationDefinitionUri != null) {
      jsonObject['presentation_definition_uri'] = presentationDefinitionUri;
    }
    if (presentationDefinition != null) {
      jsonObject['presentation_definition'] = presentationDefinition!.toJson();
    }
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
