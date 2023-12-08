import 'dart:convert';

import '../util/types.dart';
import '../util/utils.dart';

class OidcCredentialOffer implements JsonObject {
  late String credentialIssuer;
  late List<dynamic> credentials;
  Map<String, dynamic>? grants;
  String? preAuthCode;
  bool? userPinRequired;

  OidcCredentialOffer(
      {required this.credentialIssuer,
      required this.credentials,
      this.preAuthCode,
      this.userPinRequired = false});

  OidcCredentialOffer.fromJson(dynamic data) {
    _parseJson(data);
  }

  OidcCredentialOffer.fromUri(String uri) {
    var asUri = Uri.parse(uri);
    var offer = asUri.queryParameters['credential_offer'];
    _parseJson(offer);
  }

  void _parseJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    if (jsonObject.containsKey('credential_issuer')) {
      credentialIssuer = jsonObject['credential_issuer'];
    } else {
      throw Exception(
          'credential_issuer property is needed in OpenId Connect 4VC CredentialOffer');
    }

    if (jsonObject.containsKey('credentials')) {
      credentials = jsonObject['credentials'];
    } else {
      throw Exception(
          'credentials property is needed in OpenId Connect 4VC CredentialOffer');
    }

    if (jsonObject.containsKey('grants')) {
      grants = jsonObject['grants'] as Map<String, dynamic>;
      if (grants!.containsKey(
          'urn:ietf:params:oauth:grant-type:pre-authorized_code')) {
        var tmp =
            grants!['urn:ietf:params:oauth:grant-type:pre-authorized_code']
                as Map<String, dynamic>;
        if (tmp.containsKey('pre-authorized_code')) {
          preAuthCode = tmp['pre-authorized_code'];
        } else {
          throw Exception('Pre-Authorized code required');
        }

        if (tmp.containsKey('user_pin_required')) {
          userPinRequired = tmp['user_pin_required'];
        } else {
          userPinRequired = false;
        }
      }
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {
      'credential_issuer': credentialIssuer,
      'credentials': credentials
    };

    if (grants != null) {
      jsonObject['grants'] = grants;
    }

    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class OidcTokenResponse implements JsonObject {
  String? accessToken;
  String? refreshToken;
  String? cNonce;
  int? cNonceExpiresIn;
  bool? authorizationPending;
  int? interval;

  OidcTokenResponse(
      {this.accessToken,
      this.authorizationPending,
      this.cNonce,
      this.cNonceExpiresIn,
      this.interval,
      this.refreshToken});

  OidcTokenResponse.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    accessToken = jsonObject['access_token'];
    refreshToken = jsonObject['refresh_token'];
    cNonce = jsonObject['c_nonce'];
    cNonceExpiresIn = jsonObject['c_nonce_expires_in'];
    authorizationPending = jsonObject['authorization_pending'];
    interval = jsonObject['interval'];
  }
  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (accessToken != null) {
      jsonObject['access_token'] = accessToken;
    }
    if (refreshToken != null) {
      jsonObject['refresh_token'] = refreshToken;
    }
    if (cNonce != null) {
      jsonObject['c_nonce'] = cNonce;
    }
    if (cNonceExpiresIn != null) {
      jsonObject['c_nonce_expires_in'] = cNonceExpiresIn;
    }
    if (authorizationPending != null) {
      jsonObject['authorization_pending'] = authorizationPending;
    }
    if (interval != null) {
      jsonObject['interval'] = interval;
    }
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class CredentialIssuerMetaData implements JsonObject {
  late String credentialIssuer;
  String? authorizationServer;
  late String credentialEndpoint;
  String? batchCredentialEndpoint;
  late List<CredentialsSupportedObject> credentialsSupported;
  List<OidcDisplayObject>? display;

  CredentialIssuerMetaData(
      {required this.credentialIssuer,
      this.authorizationServer,
      required this.credentialEndpoint,
      this.batchCredentialEndpoint,
      required this.credentialsSupported,
      this.display});

  CredentialIssuerMetaData.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    if (jsonObject.containsKey('credential_issuer')) {
      credentialIssuer = jsonObject['credential_issuer'];
    } else {
      throw Exception('credential_issuer property is needed');
    }

    if (jsonObject.containsKey('credential_endpoint')) {
      credentialEndpoint = jsonObject['credential_endpoint'];
    } else {
      throw Exception('credential_endpoint property is needed');
    }

    authorizationServer = jsonObject['authorization_server'];
    batchCredentialEndpoint = jsonObject['batch_credential_endpoint'];

    if (jsonObject.containsKey('display')) {
      display = [];
      List tmp = jsonObject['display'];
      for (var d in tmp) {
        display!.add(OidcDisplayObject.fromJson(d));
      }
    }

    credentialsSupported = [];
    if (jsonObject.containsKey('credentials_supported')) {
      var tmp = jsonObject['credentials_supported'];
      for (var s in tmp) {
        credentialsSupported.add(CredentialsSupportedObject.fromJson(s));
      }
    }
  }

  @override
  Map<String, dynamic> toJson() {
    var jsonObject = <String, dynamic>{
      'credential_issuer': credentialIssuer,
      'credential_endpoint': credentialEndpoint
    };
    if (batchCredentialEndpoint != null) {
      jsonObject['batch_credential_endpoint'] = batchCredentialEndpoint;
    }
    if (authorizationServer != null) {
      jsonObject['authorization_server'] = authorizationServer;
    }
    if (display != null && display!.isNotEmpty) {
      var tmp = [];
      for (var d in display!) {
        tmp.add(d.toJson());
      }
      jsonObject['display'] = tmp;
    }

    if (credentialsSupported.isNotEmpty) {
      var tmp = [];
      for (var s in credentialsSupported) {
        tmp.add(s.toJson());
      }
      jsonObject['credentialSubject'] = tmp;
    }

    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class CredentialsSupportedObject implements JsonObject {
  late String format;
  String? id;
  late List<String> type;
  List<String>? context;
  List<String>? cryptographicBindingMethods;
  List<String>? cryptographicSuitesSupported;
  List<OidcDisplayObject>? display;
  List<String>? order;
  Map<String, CredentialSubjectMetadata>? credentialSubject;

  CredentialsSupportedObject(
      {required this.format,
      required this.type,
      this.id,
      this.context,
      this.display,
      this.credentialSubject,
      this.cryptographicBindingMethods,
      this.cryptographicSuitesSupported,
      this.order});

  CredentialsSupportedObject.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    if (jsonObject.containsKey('format')) {
      format = jsonObject['format'];
    } else {
      throw Exception('format property is needed');
    }

    id = jsonObject['id'];

    if (jsonObject.containsKey('types')) {
      type = jsonObject['types'].cast<String>();
    } else {
      if (jsonObject.containsKey('type')) {
        type = [jsonObject['type']];
      } else {
        throw Exception('type(s) property needed');
      }
    }

    if (jsonObject.containsKey('context')) {
      context = jsonObject['@context'].cast<String>();
    }

    if (jsonObject.containsKey('cryptographic_binding_methods_supported')) {
      cryptographicBindingMethods =
          jsonObject['cryptographic_binding_methods_supported'].cast<String>();
    }

    if (jsonObject.containsKey('cryptographic_suites_supported')) {
      cryptographicSuitesSupported =
          jsonObject['cryptographic_suites_supported'].cast<String>();
    }

    if (jsonObject.containsKey('order')) {
      order = jsonObject['order'].cast<String>();
    }

    if (jsonObject.containsKey('display')) {
      List tmp = jsonObject['display'];
      display = [];
      for (var d in tmp) {
        display!.add(OidcDisplayObject.fromJson(d));
      }
    }

    if (jsonObject.containsKey('credentialSubject')) {
      credentialSubject = {};
      Map<String, dynamic> tmp = jsonObject['credentialSubject'];
      tmp.forEach((key, value) {
        credentialSubject![key] = CredentialSubjectMetadata.fromJson(value);
      });
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {'format': format, 'type': type};
    if (id != null) {
      jsonObject['id'] = id;
    }
    if (cryptographicSuitesSupported != null) {
      jsonObject['cryptographic_suites_supported'] =
          cryptographicSuitesSupported;
    }
    if (cryptographicBindingMethods != null) {
      jsonObject['cryptographic_binding_methods_supported'] =
          cryptographicBindingMethods;
    }
    if (context != null) {
      jsonObject['context'] = context;
    }
    if (order != null) {
      jsonObject['order'] = order;
    }
    if (display != null && display!.isNotEmpty) {
      var tmp = [];
      for (var d in display!) {
        tmp.add(d.toJson());
      }
      jsonObject['display'] = tmp;
    }
    if (credentialSubject != null) {
      var tmp = <String, dynamic>{};
      credentialSubject!.forEach((key, value) {
        tmp[key] = value.toJson();
      });
      jsonObject['credentialSubject'] = tmp;
    }
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class CredentialSubjectMetadata implements JsonObject {
  bool mandatory = false;
  String? valueType;
  List<OidcDisplayObject>? display;

  CredentialSubjectMetadata(
      {this.mandatory = false, this.valueType, this.display});

  CredentialSubjectMetadata.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    mandatory = jsonObject['mandatory'] ?? false;
    valueType = jsonObject['value_type'];

    if (jsonObject.containsKey('display')) {
      List tmp = jsonObject['display'];
      display = [];
      for (var e in tmp) {
        display!.add(OidcDisplayObject.fromJson(e));
      }
    }
  }
  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {'mandatory': mandatory};
    if (valueType != null) {
      jsonObject['value_type'] = valueType;
    }
    if (display != null && display!.isNotEmpty) {
      var tmp = [];
      for (var d in display!) {
        tmp.add(d.toJson());
      }
      jsonObject['display'] = tmp;
    }
    return jsonObject;
  }
}

class OidcDisplayObject implements JsonObject {
  String? name;
  String? locale;
  UrlData? logo;
  String? description;
  String? backgroundColor;
  String? textColor;

  OidcDisplayObject(
      {this.name,
      this.locale,
      this.logo,
      this.backgroundColor,
      this.description,
      this.textColor});

  OidcDisplayObject.fromJson(dynamic data) {
    var jsonData = credentialToMap(data);
    name = jsonData['name'];
    locale = jsonData['locale'];
    description = jsonData['description'];
    backgroundColor = jsonData['background_color'];
    textColor = jsonData['text_color'];

    if (jsonData.containsKey('logo')) {
      logo = UrlData.fromJson(jsonData['logo']);
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (name != null) {
      jsonObject['name'] = name;
    }
    if (locale != null) {
      jsonObject['locale'] = locale;
    }
    if (logo != null) {
      jsonObject['logo'] = logo!.toJson();
    }
    if (description != null) {
      jsonObject['description'] = description;
    }
    if (backgroundColor != null) {
      jsonObject['background_color'];
    }
    if (textColor != null) {
      jsonObject['text_color'] = textColor;
    }
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class UrlData implements JsonObject {
  String? url;
  String? altText;

  UrlData({this.url, this.altText});

  UrlData.fromJson(dynamic data) {
    var jsonData = credentialToMap(data);
    url = jsonData['url'];
    altText = jsonData['alt_text'];
  }
  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (url != null) {
      jsonObject['url'] = url;
    }
    if (altText != null) {
      jsonObject['alt_text'] = altText;
    }
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
