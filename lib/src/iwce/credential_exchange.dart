import 'dart:convert';

import '../util/types.dart';
import '../util/utils.dart';

/// Represents a credential request as documented in inter-wallet-credential-exchange protocol.
class CredentialRequest implements JsonObject {
  List<dynamic>? _credentialTypes;

  Map<String, List<dynamic>>? _requiredProperties;

  String? _location;

  String? _challenge;

  String? _domain;

  Map<String, dynamic>? _domainSpecificExtension;

  bool? _isAppLink;

  String _type = 'CredentialRequest';

  String _acceptType = 'CredentialResponse';

  String _vpType = 'VerifiablePresentation';

  String _selectiveDisclosureType = 'HashedPlaintextCredential2021';

  CredentialRequest(
      {required List<dynamic> credentialTypes,
      required String location,
      required String challenge,
      Map<String, List<dynamic>>? requiredProperties,
      bool isAppLink = true,
      String? domain,
      Map<String, dynamic>? domainSpecificExtension})
      : _credentialTypes = credentialTypes,
        _location = location,
        _challenge = challenge,
        _requiredProperties = requiredProperties,
        _isAppLink = isAppLink,
        _domain = domain,
        _domainSpecificExtension = domainSpecificExtension;

  /// Searches base64URL encoded Response from [queryParameters] and decodes it.
  ///
  /// Expected key is 'iwce'
  CredentialRequest.fromQuery(Map<String, dynamic> queryParameters) {
    if (!queryParameters.containsKey('iwce'))
      throw FormatException('Could not find expected query parameter');
    Map<String, dynamic> json = jsonDecode(utf8.decode(
        base64Decode(Base64Codec().normalize(queryParameters['iwce']))));
    _fromJson(json);
  }

  CredentialRequest.fromJson(dynamic jsonObject) {
    var json = credentialToMap(jsonObject);
    _fromJson(json);
  }

  _fromJson(Map<String, dynamic> json) {
    if (json['type'] != _type)
      throw FormatException('Unsupported Request Type');
    if (json.containsKey('endpoint'))
      _location = json['endpoint']['location'];
    else
      _location = json['accept']['endpoint']['location'];
    _challenge = json['challenge'];
    var endpointType;
    if (json.containsKey('endpoint'))
      endpointType = json['endpoint']['type'];
    else
      endpointType = json['accept']['endpoint']['type'];
    if (endpointType == 'AppLink')
      _isAppLink = true;
    else
      _isAppLink = false;
    if (json.containsKey('domain')) _domain = json['domain'];

    if (json['accept']['type'] != _acceptType)
      throw FormatException('Unsupported Accept Type');
    if (json['accept']['verifiablePresentation']['type'] != _vpType)
      throw FormatException('Unsupported Verifiable Presentation Type');
    _credentialTypes =
        json['accept']['verifiablePresentation']['credentialTypes'];

    if (json['accept'].containsKey('selectiveDisclosure')) {
      if (json['accept']['selectiveDisclosure']['type'] !=
          _selectiveDisclosureType)
        throw FormatException('Unsupported Selective Disclosure Type');
      Map<String, dynamic> prop =
          json['accept']['selectiveDisclosure']['requiredProperties'];
      _requiredProperties = {};
      prop.forEach((key, value) {
        _requiredProperties![key] = value as List<dynamic>;
      });
    }

    if (_domain != null) {
      json.remove('type');
      json.remove('accept');
      json.remove('challenge');
      json.remove('domain');
      if (json.length > 0) _domainSpecificExtension = json;
    }
  }

  /// Returns the base64Url encoded credential request that could be used as query in an uri. It is prefixed with key 'iwce='.
  String toQuery() {
    var json = toJson();
    return 'iwce=${base64UrlEncode(utf8.encode(jsonEncode(json)))}';
  }

  /// String encoded json-representation of a credential request
  @override
  String toString() {
    return jsonEncode(toJson());
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> json = {};
    Map<String, dynamic> accept = {};
    Map<String, dynamic> vp = {};
    Map<String, dynamic> endpoint = {};

    vp['type'] = _vpType;
    vp['credentialTypes'] = _credentialTypes;
    accept['type'] = _acceptType;
    accept['verifiablePresentation'] = vp;

    if (_requiredProperties != null && _requiredProperties!.length != 0) {
      Map<String, dynamic> sd = {};
      sd['type'] = _selectiveDisclosureType;
      sd['requiredProperties'] = _requiredProperties;
      accept['selectiveDisclosure'] = sd;
    }

    if (_isAppLink!)
      endpoint['type'] = 'AppLink';
    else
      endpoint['type'] = 'WebAddress';
    endpoint['location'] = _location;

    accept['endpoint'] = endpoint;
    json['type'] = _type;
    json['accept'] = accept;
    json['challenge'] = _challenge;
    if (_domain != null) {
      json['domain'] = _domain;
      if (_domainSpecificExtension != null &&
          _domainSpecificExtension!.length > 0) {
        json.addAll(_domainSpecificExtension!);
      }
    }

    return json;
  }

  /// List of URIs denoting all requested credential types.
  List<dynamic>? get credentialTypes => _credentialTypes;

  /// Maps the requested Credential types to a list of attributes of them that should be disclosed.
  Map<String, dynamic>? get requiredProperties => _requiredProperties;

  /// URL to which the response has to be send.
  String? get location => _location;

  /// Long random String /String representation of number that has to be included in the Verifiable presentation the response contains.
  String? get challenge => _challenge;

  set challenge(String? value) {
    _challenge = value;
  }

  /// URI to announce domain specific fields.
  String? get domain => _domain;

  /// Json-Object with additional key-values pairs for one domain
  Map<String, dynamic>? get domainSpecificExtension => _domainSpecificExtension;

  /// Whether [_location] should be interpreted as App-Link or not.
  bool? get isAppLink => _isAppLink;

  /// Type of this object
  String get type => _type;

  /// Type the response to this request should have
  String get acceptType => _acceptType;

  /// Accepted Verifiable Presentation type
  String get vpType => _vpType;

  /// Accepted selective Disclosure Method
  String get selectiveDisclosureType => _selectiveDisclosureType;
}

/// Represents a credential response as documented in inter-wallet-credential-exchange protocol.
class CredentialResponse implements JsonObject {
  Map<String, dynamic>? _verifiablePresentation;

  List<dynamic>? _plaintextCredentials;

  String _type = 'CredentialResponse';

  String _sdType = 'HashedPlaintextCredential2021';

  CredentialResponse(
      {required Map<String, dynamic> verifiablePresentation,
      required List<dynamic> plaintextCredentials})
      : _verifiablePresentation = verifiablePresentation,
        _plaintextCredentials = plaintextCredentials;

  /// Searches base64URL encoded Response from [queryParameters] and decodes it.
  ///
  /// Expected key is 'iwce'
  CredentialResponse.fromQuery(Map<String, dynamic> queryParameters) {
    if (!queryParameters.containsKey('iwce'))
      throw FormatException('Could not find expected query parameter');
    Map<String, dynamic> json = jsonDecode(utf8.decode(
        base64Decode(Base64Codec().normalize(queryParameters['iwce']))));
    _fromJson(json);
  }

  CredentialResponse.fromJson(dynamic jsonObject) {
    var json = credentialToMap(jsonObject);
    _fromJson(json);
  }

  _fromJson(Map<String, dynamic> json) {
    if (json['type'] != _type)
      throw FormatException('Unsupported Response-Type');
    _verifiablePresentation = json['verifiablePresentation'];
    if (json.containsKey('selectiveDisclosure')) {
      if (json['selectiveDisclosure']['type'] != _sdType)
        throw FormatException('Unsupported Selective Disclosure Type');
      _plaintextCredentials =
          json['selectiveDisclosure']['plaintextCredentials'];
    } else
      _plaintextCredentials = [];
  }

  /// Returns the base64Url encoded credential request that could be used as query in an uri. It is prefix with key 'iwce='.
  String toQuery() {
    var json = toJson();
    return 'iwce=${base64UrlEncode(utf8.encode(jsonEncode(json)))}';
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> json = {};
    Map<String, dynamic> selectiveDisclosure = {};
    json['type'] = _type;
    json['verifiablePresentation'] = _verifiablePresentation;
    selectiveDisclosure['type'] = _sdType;
    selectiveDisclosure['plaintextCredentials'] = _plaintextCredentials;
    json['selectiveDisclosure'] = selectiveDisclosure;
    return json;
  }

  /// String encoded json-representation of a credential response
  @override
  String toString() {
    return jsonEncode(toJson());
  }

  /// The Verifiable Presentation containing the requested Verifiable Credentials
  Map<String, dynamic>? get verifiablePresentation => _verifiablePresentation;

  /// List of plaintext Credentials with some values disclosed
  List<dynamic>? get plaintextCredentials => _plaintextCredentials;

  /// Type of this object.
  String get type => _type;

  /// Type of supported selective disclosure method
  String get selectiveDisclosureType => _sdType;
}
