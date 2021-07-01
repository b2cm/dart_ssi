import 'dart:convert';

/// Represents a credential request as documented in inter-wallet-credential-exchange protocol.
class CredentialRequest {
  List<dynamic>? credentialTypes;
  Map<String, dynamic>? requiredProperties;
  String? location;
  String? challenge;
  String? domain;
  bool? isAppLink;
  String type = 'CredentialRequest';
  String acceptType = 'CredentialResponse';
  String vpType = 'VerifiablePresentation';
  String selectiveDisclosureType = 'HashedPlaintextCredential2021';

  CredentialRequest(this.credentialTypes, this.location, this.challenge,
      [this.requiredProperties, this.isAppLink = true, this.domain]);

  /// Generates credential request from base64Url encoded [query]
  CredentialRequest.fromQuery(String query) {
    Map<String, dynamic> json = jsonDecode(utf8.decode(base64Decode(query)));
    if (json['type'] != type) throw FormatException('Unsupported Request Type');

    location = json['endpoint']['location'];
    challenge = json['challenge'];
    var endpointType = json['endpoint']['type'];
    if (endpointType == 'AppLink')
      isAppLink = true;
    else
      isAppLink = false;
    if (json.containsKey('domain')) domain = json['domain'];

    if (json['accept']['type'] != acceptType)
      throw FormatException('Unsupported Accept Type');
    if (json['accept']['verifiablePresentation']['type'] != vpType)
      throw FormatException('Unsupported Verifiable Presentation Type');
    credentialTypes =
        json['accept']['verifiablePresentation']['credentialTypes'];

    if (json['accept'].containsKey('selectiveDisclosure')) {
      if (json['accept']['selectiveDisclosure']['type'] !=
          selectiveDisclosureType)
        throw FormatException('Unsupported Selective Disclosure Type');
      requiredProperties =
          json['accept']['selectiveDisclosure']['requiredProperties'];
    }
  }

  /// Returns the base64Url encoded credential request that could be used as query in an uri.
  String toQuery() {
    var json = _toJson();
    return base64UrlEncode(utf8.encode(jsonEncode(json)));
  }

  @override
  String toString() {
    return jsonEncode(_toJson());
  }

  Map<String, dynamic> _toJson() {
    Map<String, dynamic> json = {};
    Map<String, dynamic> accept = {};
    Map<String, dynamic> vp = {};
    Map<String, dynamic> endpoint = {};

    vp['type'] = vpType;
    vp['credentialTypes'] = credentialTypes;
    accept['type'] = acceptType;
    accept['verifiablePresentation'] = vp;

    if (requiredProperties != null && requiredProperties!.length != 0) {
      Map<String, dynamic> sd = {};
      sd['type'] = selectiveDisclosureType;
      sd['requiredProperties'] = requiredProperties;
      accept['selectiveDisclosure'] = sd;
    }

    if (isAppLink!)
      endpoint['type'] = 'AppLink';
    else
      endpoint['type'] = 'WebAddress';
    endpoint['location'] = location;

    json['type'] = type;
    json['accept'] = accept;
    json['endpoint'] = endpoint;
    json['challenge'] = challenge;
    if (domain != null) {
      json['domain'] = domain;
    }

    return json;
  }
}

/// Represents a credential response as documented in inter-wallet-credential-exchange protocol.
class CredentialResponse {
  Map<String, dynamic>? verifiablePresentation;
  List<dynamic>? plaintextCredentials;
  String type = 'CredentialResponse';

  CredentialResponse(this.verifiablePresentation, this.plaintextCredentials);

  /// Generates credential request from base64Url encoded [query]
  CredentialResponse.fromQuery(String query) {
    Map<String, dynamic> json = jsonDecode(utf8.decode(base64Decode(query)));
    if (json['type'] != type)
      throw FormatException('Unsupported Response-Type');
    verifiablePresentation = json['verifiablePresentation'];
    if (json.containsKey('selectiveDisclosure'))
      plaintextCredentials =
          json['selectiveDisclosure']['plaintextCredentials'];
    else
      plaintextCredentials = [];
  }

  /// Returns the base64Url encoded credential request that could be used as query in an uri.
  String toQuery() {
    var json = _toJson();
    return base64UrlEncode(utf8.encode(jsonEncode(json)));
  }

  Map<String, dynamic> _toJson() {
    Map<String, dynamic> json = {};
    Map<String, dynamic> selectiveDisclosure = {};
    json['type'] = type;
    json['verifiablePresentation'] = verifiablePresentation;
    selectiveDisclosure['plaintextCredentials'] = plaintextCredentials;
    json['selectiveDisclosure'] = selectiveDisclosure;
    return json;
  }

  @override
  String toString() {
    return jsonEncode(_toJson());
  }
}
