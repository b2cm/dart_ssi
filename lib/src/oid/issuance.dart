import 'package:dart_ssi/src/oid/dcql.dart';

import '../util/types.dart';
import '../util/utils.dart';

class OidCredentialOffer extends JsonObject {
  late String credentialIssuer;
  // draft 12: List of configuration ids; Draft 11 either configurationId or CredentialsSupportedObject
  List<dynamic>? credentials;

  /// Required in draft 13
  List<String>? credentialConfigurationIds;
  Map<String, GrantType>? grants;

  OidCredentialOffer({
    required this.credentialIssuer,
    this.credentials,
    this.credentialConfigurationIds,
    this.grants,
  });

  OidCredentialOffer.fromJson(dynamic data) {
    _parseJson(data);
  }

  OidCredentialOffer.fromUri(String uri) {
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
      List tmp = jsonObject['credentials'];
      credentials = [];
      for (var o in tmp) {
        if (o is String) {
          credentials!.add(o);
        } else {
          credentials!.add(CredentialsSupportedObject.fromJson(o));
        }
      }
    }

    if (jsonObject.containsKey('credential_configuration_ids')) {
      credentialConfigurationIds =
          (jsonObject['credential_configuration_ids'] as List).cast<String>();
    }

    if (jsonObject.containsKey('grants')) {
      var grantsTmp = jsonObject['grants'] as Map<String, dynamic>;
      grants = grantsTmp.map((key, value) =>
          MapEntry(key, GrantType.fromTypeAndJson(key, value as Map)));
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {'credential_issuer': credentialIssuer};

    if (credentialConfigurationIds != null) {
      jsonObject['credential_configuration_ids'] = credentialConfigurationIds;
    }

    if (credentials != null) {
      List tmp = [];
      for (var o in credentials!) {
        if (o is String) {
          tmp.add(o);
        } else {
          tmp.add(o.toJson());
        }
      }
      jsonObject['credentials'] = tmp;
    }

    if (grants != null) {
      jsonObject['grants'] =
          grants!.map((key, value) => MapEntry(key, value.toJson()));
    }

    return jsonObject;
  }
}

abstract class GrantType extends JsonObject {
  String get grantType;
  static final String preAuthType =
      'urn:ietf:params:oauth:grant-type:pre-authorized_code';
  static final String authType = 'authorization_code';

  GrantType();

  factory GrantType.fromTypeAndJson(String type, Map json) {
    if (type == authType) {
      return AuthorizationCodeGrant.fromJson(json);
    } else if (type == preAuthType) {
      return PreAuthCodeGrant.fromJson(json);
    } else {
      return UnsupportedGrant(
          grantType: type,
          values: json.map((key, value) => MapEntry(key as String, value)));
    }
  }
}

class UnsupportedGrant extends GrantType {
  @override
  String grantType;
  Map<String, dynamic> values;

  UnsupportedGrant({required this.grantType, required this.values});

  @override
  Map<String, dynamic> toJson() {
    return values;
  }
}

class AuthorizationCodeGrant extends GrantType {
  @override
  final String grantType = 'authorization_code';
  String? issuerState, authorizationServer;

  AuthorizationCodeGrant({this.authorizationServer, this.issuerState});

  AuthorizationCodeGrant.fromJson(dynamic json) {
    var tmp = credentialToMap(json);
    issuerState = tmp['issuer_state'];
    authorizationServer = tmp['authorization_server'];
  }
  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (issuerState != null) {
      jsonObject['issuer_state'] = issuerState;
    }
    if (authorizationServer != null) {
      jsonObject['authorization_server'] = authorizationServer;
    }
    return jsonObject;
  }
}

class PreAuthCodeGrant extends GrantType {
  @override
  final String grantType =
      'urn:ietf:params:oauth:grant-type:pre-authorized_code';
  late String preAuthCode;

  /// This is for backwards compatibility with draft 11 and 12, where user_pin_required was used
  bool? txCode;
  String? txCodeInputMethod, txCodeDescription;
  int? txCodeLength;
  int? interval;
  String? authorizationServer;

  PreAuthCodeGrant(
      {required this.preAuthCode,
      this.txCodeDescription,
      this.authorizationServer,
      this.interval,
      this.txCode,
      this.txCodeInputMethod,
      this.txCodeLength});

  PreAuthCodeGrant.fromJson(dynamic json) {
    var tmp = credentialToMap(json);

    if (tmp.containsKey('pre-authorized_code')) {
      preAuthCode = tmp['pre-authorized_code'];
    } else {
      throw Exception('pre-auth code required');
    }

    authorizationServer = tmp['authorization_server'];
    interval = tmp['interval'];

    if (tmp.containsKey('tx_code')) {
      txCode = true;
      Map txCodeDetails = tmp['tx_code'];
      txCodeInputMethod = txCodeDetails['input_mode'];
      txCodeLength = txCodeDetails['length'];
      txCodeDescription = txCodeDetails['description'];
    } else {
      txCode = false;
    }

    if (tmp.containsKey('user_pin_required')) {
      txCode = tmp['user_pin_required'];
    } else {
      txCode ??= false;
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> json = {'pre-authorized_code': preAuthCode};
    if (authorizationServer != null) {
      json['authorization_server'] = authorizationServer;
    }
    if (interval != null) {
      json['interval'] = interval;
    }
    if (txCode != null) {
      if (txCode! ||
          txCodeDescription != null ||
          txCodeLength != null ||
          txCodeInputMethod != null) {
        var txMap = {};
        if (txCodeInputMethod != null) {
          txMap['input_mode'] = txCodeInputMethod;
        }
        if (txCodeLength != null) {
          txMap['length'] = txCodeLength;
        }
        if (txCodeDescription != null) {
          txMap['description'] = txCodeDescription;
        }

        json['tx_code'] = txMap;
      }
    }

    return json;
  }
}

class AuthorizationDetailsObject extends JsonObject {
  final String type = 'openid_credential';
  String? credentialConfigurationId;
  String? format;
  List<String>? credentialIdentifiers;
  // Common Data fields per RFC 9396 Sec 2.2
  List<String>? locations, actions, dataTypes, privileges;
  String? identifier;
  //credential specific
  List<String>? credentialType;
  Map<String, dynamic>? claims;
  List<String>? context;

  AuthorizationDetailsObject(
      {this.format,
      this.credentialConfigurationId,
      this.credentialIdentifiers,
      this.actions,
      this.dataTypes,
      this.identifier,
      this.locations,
      this.privileges,
      this.context,
      this.claims,
      this.credentialType});

  factory AuthorizationDetailsObject.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    var type = jsonObject['type'];
    if (type != 'openid_credential') {
      throw Exception('Unexpected type $type in Authorization details object');
    }

    var configId = jsonObject['credential_configuration_id'];
    var format = jsonObject['format'];

    List? actions = jsonObject['actions'],
        locations = jsonObject['locations'],
        dataTypes = jsonObject['datatypes'],
        privileges = jsonObject['privileges'];
    String? id = jsonObject['identifier'];

    List<String>? credentialIdentifiers;
    if (jsonObject.containsKey('credential_identifiers')) {
      credentialIdentifiers =
          (jsonObject['credential_identifiers'] as List).cast<String>();
    }
    if (format == OidCredentialFormat.ldpVc ||
        format == OidCredentialFormat.jwtVcJsonLd) {
      Map definition = jsonObject['credential_definition'];
      List? context = definition['@context'];
      List? vcType = definition['type'] ?? definition['types'];
      Map<String, dynamic>? subject;
      if (definition.containsKey('credentialSubject')) {
        subject = _parseStuff(definition['credentialSubject']);
      }

      return AuthorizationDetailsObject(
          format: format,
          context: context?.cast<String>(),
          credentialType: vcType?.cast<String>(),
          claims: subject,
          credentialIdentifiers: credentialIdentifiers,
          actions: actions?.cast<String>(),
          dataTypes: dataTypes?.cast<String>(),
          identifier: id,
          locations: locations?.cast<String>(),
          privileges: privileges?.cast<String>());
    } else if (format == OidCredentialFormat.jwtVcJson) {
      Map definition = jsonObject['credential_definition'];
      List? vcType = definition['type'] ?? definition['types'];
      Map<String, dynamic>? subject;
      if (definition.containsKey('credentialSubject')) {
        subject = _parseStuff(definition['credentialSubject']);
      }
      return AuthorizationDetailsObject(
          format: format,
          credentialType: vcType?.cast<String>(),
          claims: subject,
          credentialIdentifiers: credentialIdentifiers,
          actions: actions?.cast<String>(),
          dataTypes: dataTypes?.cast<String>(),
          identifier: id,
          locations: locations?.cast<String>(),
          privileges: privileges?.cast<String>());
    } else if (format == OidCredentialFormat.msoMdoc) {
      String? doctype = jsonObject['doctype'];
      Map<String, Map<String, CredentialSubjectMetadata>>? claims;
      if (jsonObject.containsKey('claims')) {
        Map tmp = jsonObject['claims'];
        claims = tmp.map((key, value) => MapEntry(
            key as String,
            (value as Map).map((key, value) => MapEntry(
                key as String, CredentialSubjectMetadata.fromJson(value)))));
      }

      return AuthorizationDetailsObject(
          format: format,
          claims: claims,
          credentialType: doctype == null ? null : [doctype],
          credentialIdentifiers: credentialIdentifiers,
          actions: actions?.cast<String>(),
          dataTypes: dataTypes?.cast<String>(),
          identifier: id,
          locations: locations?.cast<String>(),
          privileges: privileges?.cast<String>());
    } else if (format == OidCredentialFormat.sdJwt) {
      String vct = jsonObject['vct'];
      Map<String, dynamic>? claims;
      if (jsonObject.containsKey('claims')) {
        claims = _parseStuff(jsonObject['claims']);
      }
      return AuthorizationDetailsObject(
          format: format,
          claims: claims,
          credentialType: [vct],
          credentialIdentifiers: credentialIdentifiers,
          actions: actions?.cast<String>(),
          dataTypes: dataTypes?.cast<String>(),
          identifier: id,
          locations: locations?.cast<String>(),
          privileges: privileges?.cast<String>());
    } else {
      return AuthorizationDetailsObject(
          credentialConfigurationId: configId,
          credentialIdentifiers: credentialIdentifiers,
          actions: actions?.cast<String>(),
          dataTypes: dataTypes?.cast<String>(),
          identifier: id,
          locations: locations?.cast<String>(),
          privileges: privileges?.cast<String>());
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {'type': type};
    if (credentialConfigurationId != null) {
      jsonObject['credential_configuration_id'] = credentialConfigurationId;
    }
    if (locations != null) {
      jsonObject['locations'] = locations;
    }
    if (actions != null) {
      jsonObject['actions'] = actions;
    }
    if (dataTypes != null) {
      jsonObject['datatypes'] = dataTypes;
    }
    if (privileges != null) {
      jsonObject['privileges'] = privileges;
    }
    if (identifier != null) {
      jsonObject['identifier'] = identifier;
    }
    if (credentialIdentifiers != null) {
      jsonObject['credential_identifiers'] = credentialIdentifiers;
    }
    if (format != null) {
      jsonObject['format'] = format;

      if (format == OidCredentialFormat.ldpVc ||
          format == OidCredentialFormat.jwtVcJson ||
          format == OidCredentialFormat.jwtVcJsonLd) {
        var definition = <String, dynamic>{};
        if (context != null) {
          definition['@context'] = context;
        }
        if (credentialType != null) {
          definition['type'] = credentialType;
        }
        if (claims != null) {
          definition['credentialSubject'] = _stuffToJson(claims!);
        }
        jsonObject['credential_definition'] = definition;
      } else if (format == OidCredentialFormat.msoMdoc) {
        if (credentialType != null) {
          jsonObject['doctype'] = credentialType!.firstOrNull;
        }
        if (claims != null) {
          jsonObject['claims'] = _stuffToJson(claims!);
        }
      } else if (format == OidCredentialFormat.sdJwt) {
        if (credentialType != null) {
          jsonObject['vct'] = credentialType!.firstOrNull;
        }
        if (claims != null) {
          jsonObject['claims'] = _stuffToJson(claims!);
        }
      }
    }

    return jsonObject;
  }
}

class OidTokenResponse extends JsonObject {
  // Parameter from RFC 6749 OAuth 2.0
  String? accessToken, tokenType;
  String? refreshToken, scope;
  int? expiresIn;

  // Parameter from oid4vci draft 11 - 13
  String? cNonce;
  int? cNonceExpiresIn;
  // Parameter from oid4vci draft 11
  bool? authorizationPending;
  int? interval;
  // Parameter from oid4vci draft 12 - 13
  List<AuthorizationDetailsObject>? authorizationDetails;

  OidTokenResponse(
      {this.accessToken,
      this.authorizationPending,
      this.cNonce,
      this.cNonceExpiresIn,
      this.interval,
      this.refreshToken,
      this.tokenType,
      this.scope,
      this.expiresIn,
      this.authorizationDetails});

  OidTokenResponse.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    accessToken = jsonObject['access_token'];
    refreshToken = jsonObject['refresh_token'];
    tokenType = jsonObject['token_type'];
    expiresIn = jsonObject['expires_in'];
    scope = jsonObject['scope'];

    cNonce = jsonObject['c_nonce'];
    cNonceExpiresIn = jsonObject['c_nonce_expires_in'];
    authorizationPending = jsonObject['authorization_pending'];
    interval = jsonObject['interval'];

    if (jsonObject.containsKey('authorization_details')) {
      List details = jsonObject['authorization_details'];
      authorizationDetails =
          details.map((e) => AuthorizationDetailsObject.fromJson(e)).toList();
    }
  }
  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (accessToken != null) {
      jsonObject['access_token'] = accessToken;
    }
    if (tokenType != null) {
      jsonObject['token_type'] = tokenType;
    }
    if (refreshToken != null) {
      jsonObject['refresh_token'] = refreshToken;
    }
    if (scope != null) {
      jsonObject['scope'] = scope;
    }
    if (expiresIn != null) {
      jsonObject['expires_in'] = expiresIn;
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

    if (authorizationDetails != null) {
      jsonObject['authorization_details'] =
          authorizationDetails!.map((e) => e.toJson()).toList();
    }
    return jsonObject;
  }
}

class EncryptionInformation extends JsonObject {
  List<String>? algValuesSupported, encValuesSupported, zipValuesSupported;
  List<Map<String, dynamic>>? keySet;
  bool encryptionRequired;

  EncryptionInformation(
      {required this.encryptionRequired,
      this.algValuesSupported,
      this.encValuesSupported,
      this.zipValuesSupported,
      this.keySet});

  factory EncryptionInformation.fromJson(dynamic jsonObject) {
    var data = credentialToMap(jsonObject);
    Map? keySet = data['jwks'];
    List<Map<String, dynamic>>? tmp;
    if (keySet != null) {
      List keys = keySet['keys'];
      tmp = keys
          .map((e) => (e as Map).map((k, v) => MapEntry(k as String, v)))
          .toList();
    }
    return EncryptionInformation(
        encryptionRequired: data['encryption_required'],
        algValuesSupported: data.containsKey('alg_values_supported')
            ? (data['alg_values_supported'] as List).cast<String>()
            : null,
        encValuesSupported:
            (data['enc_values_supported'] as List).cast<String>(),
        zipValuesSupported: data.containsKey('zip_values_supported')
            ? (data['zip_values_supported'] as List).cast<String>()
            : null,
        keySet: tmp);
  }
  @override
  Map<String, dynamic> toJson() {
    return {
      'encryption_required': encryptionRequired,
      if (algValuesSupported != null) 'alg_vales_supported': algValuesSupported,
      'enc_values_supported': encValuesSupported,
      if (zipValuesSupported != null) 'zip_values_supported': zipValuesSupported
    };
  }
}

class CredentialIssuerMetaData extends JsonObject {
  late String credentialIssuer;
  List<String>? authorizationServer,
      credentialResponseEncryptionAlgSupported,
      credentialResponseEncryptionEncSupported,
      credentialResponseEncryptionZipSupported;
  late String credentialEndpoint;
  String? batchCredentialEndpoint,
      deferredCredentialEndpoint,
      notificationEndpoint,
      nonceEndpoint;
  bool? credentialResponseEncryptionRequired, credentialIdentifiersSupported;
  late Map<String, CredentialsSupportedObject> credentialsSupported;
  List<OidDisplayObject>? display;

  /// If not null, batch issuance at credential endpoint is supported
  int? batchCredentialIssuanceBatchSize;
  EncryptionInformation? credentialRequestEncryption;

  CredentialIssuerMetaData(
      {required this.credentialIssuer,
      this.authorizationServer,
      required this.credentialEndpoint,
      this.batchCredentialEndpoint,
      required this.credentialsSupported,
      this.display,
      this.batchCredentialIssuanceBatchSize,
      this.credentialIdentifiersSupported,
      this.credentialRequestEncryption,
      this.credentialResponseEncryptionAlgSupported,
      this.credentialResponseEncryptionEncSupported,
      this.credentialResponseEncryptionRequired,
      this.credentialResponseEncryptionZipSupported,
      this.deferredCredentialEndpoint,
      this.nonceEndpoint,
      this.notificationEndpoint});

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

    if (jsonObject.containsKey('authorization_servers')) {
      authorizationServer =
          (jsonObject['authorization_servers'] as List).cast<String>();
    }

    batchCredentialEndpoint = jsonObject['batch_credential_endpoint'];
    deferredCredentialEndpoint = jsonObject['deferred_credential_endpoint'];
    notificationEndpoint = jsonObject['notification_endpoint'];
    nonceEndpoint = jsonObject['nonce_endpoint'];

    // request encryption, introduced with V1
    if (jsonObject.containsKey('credential_request_encryption')) {
      credentialRequestEncryption = EncryptionInformation.fromJson(
          jsonObject['credential_request_encryption']);
    }

    // batch issuance as per draft 14
    batchCredentialIssuanceBatchSize =
        jsonObject['batch_credential_issuance']?['batch_size'];

    // encryption stuff as per draft 12
    if (jsonObject
        .containsKey('credential_response_encryption_alg_values_supported')) {
      credentialResponseEncryptionAlgSupported =
          (jsonObject['credential_response_encryption_alg_values_supported']
                  as List)
              .cast<String>();
    }
    if (jsonObject
        .containsKey('credential_response_encryption_enc_values_supported')) {
      credentialResponseEncryptionEncSupported =
          (jsonObject['credential_response_encryption_enc_values_supported']
                  as List)
              .cast<String>();
    }
    if (jsonObject.containsKey('require_credential_response_encryption')) {
      credentialResponseEncryptionRequired =
          jsonObject['require_credential_response_encryption'];
    }

    // encryption stuff as per draft 13
    if (jsonObject.containsKey('credential_response_encryption')) {
      var tmp = jsonObject['credential_response_encryption'] as Map;
      credentialResponseEncryptionAlgSupported =
          (tmp['alg_values_supported'] as List).cast<String>();
      credentialResponseEncryptionEncSupported =
          (tmp['enc_values_supported'] as List).cast<String>();
      credentialResponseEncryptionZipSupported =
          (tmp['zip_values_supported'] as List?)?.cast<String>();
      credentialResponseEncryptionRequired = tmp['encryption_required'];
    }

    credentialIdentifiersSupported =
        jsonObject['credential_identifiers_supported'];

    if (jsonObject.containsKey('display')) {
      display = [];
      List tmp = jsonObject['display'];
      for (var d in tmp) {
        display!.add(OidDisplayObject.fromJson(d));
      }
    }

    // draft 12 / 11
    if (jsonObject.containsKey('credentials_supported')) {
      credentialsSupported = {};
      var tmp = jsonObject['credentials_supported'];
      if (tmp is Map) {
        // draft 12
        for (var s in tmp.keys) {
          print(tmp[s]);
          var support = CredentialsSupportedObject.fromJson(tmp[s]);
          support.credentialId = s;
          credentialsSupported[s] = support;
        }
      } else {
        // draft 11
        tmp as List;
        int c = 0;
        for (Map s in tmp) {
          var id = s['id'];
          var support = CredentialsSupportedObject.fromJson(s);
          support.credentialId = id;
          credentialsSupported[id ?? c.toString()] = support;
          c++;
        }
      }
    }
    // draft 13
    if (jsonObject.containsKey('credential_configurations_supported')) {
      credentialsSupported = {};
      Map tmp = jsonObject['credential_configurations_supported'];
      for (var s in tmp.keys) {
        credentialsSupported[s] = CredentialsSupportedObject.fromJson(tmp[s]);
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
    if (deferredCredentialEndpoint != null) {
      jsonObject['deferred_credential_endpoint'] = deferredCredentialEndpoint;
    }
    if (authorizationServer != null) {
      jsonObject['authorization_servers'] = authorizationServer;
    }
    if (notificationEndpoint != null) {
      jsonObject['notification_endpoint'] = notificationEndpoint;
    }
    if (nonceEndpoint != null) {
      jsonObject['nonce_endpoint'] = nonceEndpoint;
    }
    if (credentialRequestEncryption != null) {
      jsonObject['credential_request_encryption'] =
          credentialRequestEncryption!.toJson();
    }
    if (credentialResponseEncryptionEncSupported != null &&
        credentialResponseEncryptionAlgSupported != null &&
        credentialResponseEncryptionRequired != null) {
      Map<String, dynamic> tmp = {};
      tmp['alg_values_supported'] = credentialResponseEncryptionAlgSupported;
      tmp['enc_values_supported'] = credentialResponseEncryptionEncSupported;
      tmp['encryption_required'] = credentialResponseEncryptionRequired;
      jsonObject['credential_response_encryption'] = tmp;
    }
    if (batchCredentialIssuanceBatchSize != null) {
      jsonObject['batch_credential_issuance'] = {
        'batch_size': batchCredentialIssuanceBatchSize
      };
    }
    if (credentialIdentifiersSupported != null) {
      jsonObject['credential_identifiers_supported'] =
          credentialIdentifiersSupported;
    }
    if (display != null && display!.isNotEmpty) {
      var tmp = [];
      for (var d in display!) {
        tmp.add(d.toJson());
      }
      jsonObject['display'] = tmp;
    }

    if (credentialsSupported.isNotEmpty) {
      jsonObject['credential_configurations_supported'] = credentialsSupported
          .map((key, value) => MapEntry(key, value.toJson()));
    }

    return jsonObject;
  }
}

class ClaimsDescriptionObject extends JsonObject {
  ClaimPathPointer path;
  bool mandatory;
  List<OidDisplayObject>? display;

  ClaimsDescriptionObject(
      {required this.path, this.mandatory = false, this.display});

  factory ClaimsDescriptionObject.fromJson(dynamic json) {
    var data = credentialToMap(json);
    List<OidDisplayObject>? display;
    if (data.containsKey('display')) {
      display = (data['display'] as List)
          .map((e) => OidDisplayObject.fromJson(e))
          .toList();
    }

    return ClaimsDescriptionObject(
        path: ClaimPathPointer.fromJson(data['path']),
        mandatory: data['mandatory'] ?? false,
        display: display);
  }

  @override
  Map<String, dynamic> toJson() {
    var jsonData = <String, dynamic>{'path': path.toJson()};
    if (mandatory) {
      jsonData['mandatory'] = mandatory;
    }
    if (display != null && display!.isNotEmpty) {
      jsonData['display'] = display!.map((e) => e.toJson()).toList();
    }
    return jsonData;
  }
}

class KeyAttestationDetails extends JsonObject {
  List<String>? keyStorage;
  List<String>? userAuthentication;

  KeyAttestationDetails({this.keyStorage, this.userAuthentication});

  factory KeyAttestationDetails.fromJson(dynamic jsonData) {
    var data = credentialToMap(jsonData);
    return KeyAttestationDetails(
        keyStorage: (data['key_storage'] as List?)?.cast<String>(),
        userAuthentication:
            (data['user_authentication'] as List?)?.cast<String>());
  }

  @override
  Map<String, dynamic> toJson() {
    var jsonData = <String, dynamic>{};
    if (keyStorage != null) {
      jsonData['key_storage'] = keyStorage;
    }
    if (userAuthentication != null) {
      jsonData['user_authentication'] = userAuthentication;
    }
    return jsonData;
  }
}

class ProofTypesSupportedDetails extends JsonObject {
  /// alg values might be strings (jwt/ldp_vp) or ints (cwt).
  List<dynamic> signingAlgValuesSupported;
  KeyAttestationDetails? keyAttestationRequired;

  ProofTypesSupportedDetails(
      {required this.signingAlgValuesSupported, this.keyAttestationRequired});

  factory ProofTypesSupportedDetails.fromJson(dynamic jsonData) {
    var data = credentialToMap(jsonData);
    List sigValues;
    if (data.containsKey('proof_signing_alg_values_supported')) {
      sigValues = data['proof_signing_alg_values_supported'] as List;
    } else {
      throw Exception(
          'proof_signing_alg_values_supported property is mandatory');
    }
    KeyAttestationDetails? keyDetails;
    if (data.containsKey('key_attestations_required')) {
      keyDetails =
          KeyAttestationDetails.fromJson(data['key_attestations_required']);
    }

    return ProofTypesSupportedDetails(
        signingAlgValuesSupported: sigValues,
        keyAttestationRequired: keyDetails);
  }

  @override
  Map<String, dynamic> toJson() {
    var jsonData = <String, dynamic>{
      'proof_signing_alg_values_supported': signingAlgValuesSupported
    };
    if (keyAttestationRequired != null) {
      jsonData['key_attestations_required'] = keyAttestationRequired!.toJson();
    }
    return jsonData;
  }
}

class CredentialsSupportedObject extends JsonObject {
  String format;
  String? scope;
  List<dynamic>? credentialSigningAlgValues;
  List<String>? cryptographicBindingMethods,

      /// in draft 11 and 12 called cryptographic_suites_supported

      order;

  /// in draft 12 this is only a list of the proof types,
  /// therefor the List of supported algs in ProofTypesSupportedObject is always empty
  Map<String, ProofTypesSupportedDetails>? proofTypesSupported;
  List<OidDisplayObject>? display;

  /// credential specific, used in draft 11-14
  Map<String, dynamic>? claims;

  /// The Object behind 'claims' since draft 15
  ///
  /// It got its own entry here, because changes were too substantial
  List<ClaimsDescriptionObject>? claimDescriptions;

  /// For mso_mdoc and dc+sd-jwt only the first entry is used
  List<String>? credentialType;

  /// only used for ldp_vc, jwt_vc_json-ld and jwt_vc_json
  List<String>? context;
  String? credentialId;

  CredentialsSupportedObject(
      {required this.format,
      this.order,
      this.scope,
      this.display,
      this.cryptographicBindingMethods,
      this.credentialSigningAlgValues,
      this.proofTypesSupported,
      this.credentialType,
      this.claims,
      this.claimDescriptions,
      this.context,
      this.credentialId});

  factory CredentialsSupportedObject.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    var format = jsonObject['format'];
    String? scope = jsonObject['scope'];
    List<dynamic>? cs;
    List<String>? cbm, o;
    Map<String, ProofTypesSupportedDetails>? pt;
    List<OidDisplayObject>? display;
    if (jsonObject.containsKey('cryptographic_binding_methods_supported')) {
      cbm = (jsonObject['cryptographic_binding_methods_supported'] as List)
          .cast<String>();
    }
    if (jsonObject.containsKey('proof_types_supported')) {
      var tmp = jsonObject['proof_types_supported'];
      pt = {};
      if (tmp is Map) {
        //draft 13 and above
        for (var k in tmp.keys) {
          Map v = tmp[k];
          var l = ProofTypesSupportedDetails.fromJson(v);
          pt[k] = l;
        }
      } else {
        tmp as List;
        for (var k in tmp) {
          pt[k] = ProofTypesSupportedDetails(signingAlgValuesSupported: []);
        }
      }
    }
    if (jsonObject.containsKey('credential_signing_alg_values_supported')) {
      cs = (jsonObject['credential_signing_alg_values_supported'] as List);
    }
    if (jsonObject.containsKey('cryptographic_suites_supported')) {
      cs =
          (jsonObject['cryptographic_suites_supported'] as List).cast<String>();
    }
    if (jsonObject.containsKey('order')) {
      o = (jsonObject['order'] as List).cast<String>();
    }
    if (jsonObject.containsKey('display')) {
      List tmp = jsonObject['display'];
      display = tmp.map((e) => OidDisplayObject.fromJson(e)).toList();
    }

    // with OID4VCI 1.0 credential_metadata key spawned
    // its object contains display and claims
    Map? credentialMetadata;
    List<ClaimsDescriptionObject>? descriptionObjects;
    if (jsonObject.containsKey('credential_metadata')) {
      credentialMetadata = jsonObject['credential_metadata'];
      if (credentialMetadata!.containsKey('display')) {
        List tmp = credentialMetadata['display'];
        display = tmp.map((e) => OidDisplayObject.fromJson(e)).toList();
      }
      if (credentialMetadata.containsKey('claims')) {
        descriptionObjects = (credentialMetadata['claims'] as List)
            .map((e) => ClaimsDescriptionObject.fromJson(e))
            .toList();
      }
    }

    if (format == OidCredentialFormat.msoMdoc) {
      Map<String, dynamic>? claims;
      if (jsonObject.containsKey('claims')) {
        dynamic tmp = jsonObject['claims'];
        if (tmp is List) {
          descriptionObjects =
              tmp.map((e) => ClaimsDescriptionObject.fromJson(e)).toList();
        } else {
          claims = _parseStuff(tmp);
        }
      }
      return CredentialsSupportedObject(
          credentialType: [jsonObject['doctype']!],
          claims: claims,
          order: o,
          format: format,
          scope: scope,
          proofTypesSupported: pt,
          display: display,
          cryptographicBindingMethods: cbm,
          claimDescriptions: descriptionObjects,
          credentialSigningAlgValues: cs);
    } else if (format == OidCredentialFormat.sdJwt ||
        format == OidCredentialFormat.sdJwtDc) {
      Map<String, dynamic>? claims;

      String cType;
      // draft 11 and 12 do not mention sd-jwt, therefor we assume it is handled as other jwt types
      if (jsonObject.containsKey('credential_definition')) {
        Map definition = jsonObject['credential_definition'];
        cType = definition['type'];
        if (definition.containsKey('claims')) {
          claims = _parseStuff(definition['claims']);
        }
        if (definition.containsKey('credentialSubject')) {
          claims = _parseStuff(definition['credentialSubject']);
        }
      } else {
        // draft 13
        cType = jsonObject['vct'];
        if (jsonObject.containsKey('claims')) {
          dynamic tmp = jsonObject['claims'];
          if (tmp is List) {
            descriptionObjects =
                tmp.map((e) => ClaimsDescriptionObject.fromJson(e)).toList();
          } else {
            claims = _parseStuff(jsonObject['claims']);
          }
        }
      }
      return CredentialsSupportedObject(
          credentialType: [cType],
          claims: claims,
          claimDescriptions: descriptionObjects,
          order: o,
          format: format,
          scope: scope,
          proofTypesSupported: pt,
          display: display,
          cryptographicBindingMethods: cbm,
          credentialSigningAlgValues: cs);
    } else if (format == OidCredentialFormat.ldpVc ||
        format == OidCredentialFormat.jwtVcJsonLd) {
      List? context, type;
      Map<String, dynamic>? claims;
      if (jsonObject.containsKey('credential_definition')) {
        Map definition = jsonObject['credential_definition'];
        context = definition['@context'];
        type = definition['type'];

        if (definition.containsKey('credentialSubject')) {
          claims = _parseStuff(definition['credentialSubject']);
        }
      } else {
        type = jsonObject['types'];
        context = jsonObject['@context'];
        if (jsonObject.containsKey('credentialSubject')) {
          claims = _parseStuff(jsonObject['credentialSubject']);
        }
      }
      if (jsonObject.containsKey('claims')) {
        var tmp = jsonObject['claims'] as List;
        descriptionObjects =
            tmp.map((e) => ClaimsDescriptionObject.fromJson(e)).toList();
      }
      return CredentialsSupportedObject(
          claims: claims,
          claimDescriptions: descriptionObjects,
          order: o,
          credentialSigningAlgValues: cs,
          cryptographicBindingMethods: cbm,
          display: display,
          proofTypesSupported: pt,
          scope: scope,
          format: format,
          context: context!.cast<String>(),
          credentialType: type!.cast<String>());
    } else if (format == OidCredentialFormat.jwtVcJson) {
      Map<String, dynamic>? claims;
      List type;
      if (jsonObject.containsKey('credential_definition')) {
        Map definition = jsonObject['credential_definition'];
        type = definition['type'];

        if (definition.containsKey('credentialSubject')) {
          claims = _parseStuff(definition['credentialSubject']);
        }
      } else {
        type = jsonObject['types'];
        if (jsonObject.containsKey('credentialSubject')) {
          claims = _parseStuff(jsonObject['credentialSubject']);
        }
      }
      if (jsonObject.containsKey('claims')) {
        var tmp = jsonObject['claims'] as List;
        descriptionObjects =
            tmp.map((e) => ClaimsDescriptionObject.fromJson(e)).toList();
      }
      return CredentialsSupportedObject(
          claims: claims,
          claimDescriptions: descriptionObjects,
          order: o,
          credentialSigningAlgValues: cs,
          cryptographicBindingMethods: cbm,
          display: display,
          proofTypesSupported: pt,
          scope: scope,
          format: format,
          credentialType: type.cast<String>());
    } else {
      return CredentialsSupportedObject(
          format: format,
          credentialSigningAlgValues: cs,
          cryptographicBindingMethods: cbm,
          display: display,
          proofTypesSupported: pt,
          scope: scope);
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {'format': format};
    if (scope != null) {
      jsonObject['scope'] = scope;
    }

    if (cryptographicBindingMethods != null) {
      jsonObject['cryptographic_binding_methods_supported'] =
          cryptographicBindingMethods;
    }
    if (credentialSigningAlgValues != null) {
      jsonObject['credential_signing_alg_values_supported'] =
          credentialSigningAlgValues;
    }
    if (proofTypesSupported != null) {
      jsonObject['proof_types_supported'] = proofTypesSupported!
          .map((key, value) => MapEntry(key, value.toJson()));
    }

    if (display != null && display!.isNotEmpty) {
      var tmp = [];
      for (var d in display!) {
        tmp.add(d.toJson());
      }
      jsonObject['display'] = tmp;
    }

    if (order != null) {
      jsonObject['order'] = order;
    }

    if (format == OidCredentialFormat.msoMdoc) {
      if (credentialType != null) {
        jsonObject['doctype'] = credentialType!.firstOrNull;
      }
      if (claims != null) {
        jsonObject['claims'] = _stuffToJson(claims!);
      }
    } else if (format == OidCredentialFormat.ldpVc ||
        format == OidCredentialFormat.jwtVcJsonLd ||
        format == OidCredentialFormat.jwtVcJson) {
      var definition = <String, dynamic>{};
      if (context != null) {
        definition['@context'] = context;
      }
      definition['type'] = credentialType;
      if (claims != null) {
        definition['credentialSubject'] = _stuffToJson(claims!);
      }
      jsonObject['credential_definition'] = definition;
    } else if (format == OidCredentialFormat.sdJwt ||
        format == OidCredentialFormat.sdJwtDc) {
      if (credentialType != null) {
        jsonObject['vct'] = credentialType!.firstOrNull;
      }
      if (claims != null) {
        jsonObject['claims'] = _stuffToJson(claims!);
      }
    }

    if (claimDescriptions != null) {
      jsonObject['claims'] = claimDescriptions!.map((e) => e.toJson()).toList();
    }

    return jsonObject;
  }
}

class CredentialSubjectMetadata extends JsonObject {
  bool mandatory = false;
  String? valueType;
  List<OidDisplayObject>? display;

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
        display!.add(OidDisplayObject.fromJson(e));
      }
    }
  }

  static bool isCredentialSubjectMetadata(Map candidate) {
    return candidate.containsKey('display') ||
        candidate.containsKey('mandatory') ||
        candidate.containsKey('value_type') ||
        candidate.isEmpty;
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (mandatory) {
      jsonObject['mandatory'] = mandatory;
    }
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

class OidDisplayObject extends JsonObject {
  String? name;
  String? locale;
  UrlData? logo;
  String? description;
  String? backgroundColor;
  String? textColor;

  OidDisplayObject(
      {this.name,
      this.locale,
      this.logo,
      this.backgroundColor,
      this.description,
      this.textColor});

  OidDisplayObject.fromJson(dynamic data) {
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
}

class UrlData extends JsonObject {
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
}

class OidCredentialRequest extends JsonObject {
  String? format, credentialIdentifier, credentialConfigurationId;
  Map<String, dynamic>? responseEncryptionJwk;
  String? responseEncryptionAlg, responseEncryptionEnc;

  /// Draft 11-13: there is only parameter proof; Draft 14 proofs parameter was added
  /// This Variable stores content for both, because only one of them can be present
  /// It is serialized as "proof" : {"proof_type" : "xyz" , "xyz" : "..."}, when this List contains only one element
  /// and as "proofs" : {"xyz" : ["...1", "...2", ...]}, when there are more elements.
  List<CredentialRequestProof>? proof;
  // credential specific
  List<String>? credentialType;
  List<String>? context;
  Map<String, dynamic>? claims;

  OidCredentialRequest(
      {this.format,
      this.credentialIdentifier,
      this.credentialConfigurationId,
      this.proof,
      this.responseEncryptionAlg,
      this.responseEncryptionEnc,
      this.responseEncryptionJwk,
      this.credentialType,
      this.claims,
      this.context});

  factory OidCredentialRequest.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    // Parameters for every format
    String? format = jsonObject['format'],
        credentialIdentifier = jsonObject['credential_identifier'],
        configId = jsonObject['credential_configuration_id'];
    if (format == null && credentialIdentifier == null && configId == null) {
      throw Exception(
          'Invalid Credential Request: format credential_configuration_id and credentialIdentifier null');
    }
    List<CredentialRequestProof>? proofs;
    if (jsonObject.containsKey('proof')) {
      var proof = CredentialRequestProof.fromJson(jsonObject['proof']);
      proofs = [proof];
    }
    if (jsonObject.containsKey('proofs')) {
      Map proofObject = jsonObject['proofs'];
      proofs = [];
      for (var proofType in proofObject.keys) {
        List p = proofObject[proofType];
        for (var proofValue in p) {
          proofs.add(CredentialRequestProof(
              proofType: proofType, proofValue: proofValue));
        }
      }
    }
    Map? jwk = jsonObject['credential_encryption_jwk'];
    String? enc = jsonObject['credential_response_encryption_enc'],
        alg = jsonObject['credential_response_encryption_alg'];

    if (jsonObject.containsKey('credential_response_encryption')) {
      Map tmp = jsonObject['credential_response_encryption'];
      jwk = tmp['jwk'];
      alg = tmp['alg'];
      enc = tmp['enc'];
    }

    // format specific
    if (format == OidCredentialFormat.ldpVc ||
        format == OidCredentialFormat.jwtVcJsonLd) {
      Map definition = jsonObject['credential_definition'];
      List? context = definition['@context'];
      List? vcType = definition['type'] ?? definition['types'];
      Map<String, dynamic>? subject;
      if (definition.containsKey('credentialSubject')) {
        subject = _parseStuff(definition['credentialSubject']);
      }

      return OidCredentialRequest(
          format: format,
          credentialConfigurationId: configId,
          context: context?.cast<String>(),
          credentialType: vcType?.cast<String>(),
          claims: subject,
          credentialIdentifier: credentialIdentifier,
          proof: proofs,
          responseEncryptionAlg: alg,
          responseEncryptionEnc: enc,
          responseEncryptionJwk:
              jwk?.map((key, value) => MapEntry(key as String, value)));
    } else if (format == OidCredentialFormat.jwtVcJson) {
      List vcType;
      Map<String, dynamic>? subject;
      if (jsonObject.containsKey('credential_definition')) {
        Map definition = jsonObject['credential_definition'];
        vcType = definition['type'] ?? definition['types'];

        if (definition.containsKey('credentialSubject')) {
          subject = _parseStuff(definition['credentialSubject']);
        }
      } else {
        vcType = jsonObject['type'] ?? jsonObject['types'];
        if (jsonObject.containsKey('credentialSubject')) {
          subject = _parseStuff(jsonObject['credentialSubject']);
        }
      }

      return OidCredentialRequest(
          format: format,
          credentialConfigurationId: configId,
          credentialType: vcType.cast<String>(),
          claims: subject,
          credentialIdentifier: credentialIdentifier,
          proof: proofs,
          responseEncryptionAlg: alg,
          responseEncryptionEnc: enc,
          responseEncryptionJwk:
              jwk?.map((key, value) => MapEntry(key as String, value)));
    } else if (format == OidCredentialFormat.msoMdoc) {
      String? doctype = jsonObject['doctype'];
      Map<String, dynamic>? claims;
      if (jsonObject.containsKey('claims')) {
        Map tmp = jsonObject['claims'];
        claims = _parseStuff(tmp);
      }

      return OidCredentialRequest(
          format: format,
          claims: claims,
          credentialConfigurationId: configId,
          credentialType: doctype != null ? [doctype] : null,
          credentialIdentifier: credentialIdentifier,
          proof: proofs,
          responseEncryptionAlg: alg,
          responseEncryptionEnc: enc,
          responseEncryptionJwk:
              jwk?.map((key, value) => MapEntry(key as String, value)));
    } else if (format == OidCredentialFormat.sdJwt ||
        format == OidCredentialFormat.sdJwtDc) {
      String? vct = jsonObject['vct'];
      Map<String, dynamic>? claims;
      if (jsonObject.containsKey('claims')) {
        claims = _parseStuff(jsonObject['claims']);
      }
      return OidCredentialRequest(
          format: format,
          credentialConfigurationId: configId,
          claims: claims,
          credentialType: vct != null ? [vct] : null,
          credentialIdentifier: credentialIdentifier,
          proof: proofs,
          responseEncryptionAlg: alg,
          responseEncryptionEnc: enc,
          responseEncryptionJwk:
              jwk?.map((key, value) => MapEntry(key as String, value)));
    } else {
      return OidCredentialRequest(
          credentialIdentifier: credentialIdentifier,
          credentialConfigurationId: configId,
          proof: proofs,
          responseEncryptionAlg: alg,
          responseEncryptionEnc: enc,
          responseEncryptionJwk:
              jwk?.map((key, value) => MapEntry(key as String, value)));
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (credentialIdentifier != null) {
      jsonObject['credential_identifier'] = credentialIdentifier;
    }
    if (credentialConfigurationId != null) {
      jsonObject['credential_configuration_id'] = credentialConfigurationId;
    }
    if (format != null) {
      jsonObject['format'] = format;
    }
    if (proof != null) {
      List<String> jwt = [];
      List<Map> ldp = [];
      for (var entry in proof!) {
        if (entry.proofType == 'jwt') {
          jwt.add(entry.proofValue);
        }
        if (entry.proofType == 'ldp_vp') {
          ldp.add(entry.proofValue);
        }
      }
      Map<String, dynamic> proofObject = {};
      if (jwt.isNotEmpty) {
        proofObject['jwt'] = jwt;
      }
      if (ldp.isNotEmpty) {
        proofObject['ldp_vp'] = ldp;
      }
      jsonObject['proofs'] = proofObject;
    }
    if (responseEncryptionJwk != null && responseEncryptionAlg != null) {
      Map<String, dynamic> tmp = {};
      tmp['jwk'] = responseEncryptionJwk;
      tmp['alg'] = responseEncryptionAlg;
      tmp['enc'] = responseEncryptionEnc;
      jsonObject['credential_response_encryption'] = tmp;
    }

    if (format == OidCredentialFormat.ldpVc ||
        format == OidCredentialFormat.jwtVcJsonLd ||
        format == OidCredentialFormat.jwtVcJson) {
      var definition = <String, dynamic>{};
      if (context != null) {
        definition['@context'] = context;
      }
      if (credentialType != null) {
        definition['type'] = credentialType;
      }
      if (claims != null) {
        definition['credentialSubject'] = _stuffToJson(claims!);
      }
      jsonObject['credential_definition'] = definition;
    } else if (format == OidCredentialFormat.sdJwt) {
      if (credentialType != null) {
        jsonObject['vct'] = credentialType?.firstOrNull;
      }
      if (claims != null) {
        jsonObject['claims'] = _stuffToJson(claims!);
      }
    } else if (format == OidCredentialFormat.msoMdoc) {
      if (credentialType != null) {
        jsonObject['doctype'] = credentialType!.firstOrNull;
      }
      if (claims != null) {
        jsonObject['claims'] = _stuffToJson(claims!);
      }
    }

    return jsonObject;
  }
}

class OidBatchCredentialRequest extends JsonObject {
  List<OidCredentialRequest> credentialRequests;

  OidBatchCredentialRequest(this.credentialRequests);

  factory OidBatchCredentialRequest.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    List requests = jsonObject['credential_requests'];

    return OidBatchCredentialRequest(
        requests.map((e) => OidCredentialRequest.fromJson(e)).toList());
  }

  @override
  Map<String, dynamic> toJson() {
    return {
      'credential_requests': credentialRequests.map((e) => e.toJson()).toList()
    };
  }
}

class OidBatchCredentialResponse extends JsonObject {
  List<OidCredentialResponse> credentialResponses;
  String? cNonce;
  int? cNonceExpiresIn;

  OidBatchCredentialResponse(
      this.credentialResponses, this.cNonce, this.cNonceExpiresIn);

  factory OidBatchCredentialResponse.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);
    List responses = jsonObject['credential_responses'];

    return OidBatchCredentialResponse(
        responses.map((e) => OidCredentialResponse.fromJson(e)).toList(),
        jsonObject['c_nonce'],
        jsonObject['c_nonce_expires_in']);
  }
  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> data = {
      'credential_responses':
          credentialResponses.map((e) => e.toJson()).toList()
    };
    if (cNonce != null) {
      data['c_nonce'] = cNonce;
    }
    if (cNonceExpiresIn != null) {
      data['c_nonce_expires_in'] = cNonceExpiresIn;
    }

    return data;
  }
}

class CredentialRequestProof extends JsonObject {
  String proofType;
  dynamic proofValue;

  CredentialRequestProof({required this.proofType, this.proofValue});

  factory CredentialRequestProof.fromJson(dynamic jsonData) {
    var jsonObject = credentialToMap(jsonData);
    var type = jsonObject['proof_type'];

    if (type == 'jwt') {
      return CredentialRequestProof(
          proofValue: jsonObject['jwt'], proofType: type);
    } else if (type == 'cwt') {
      // removed with draft 14
      return CredentialRequestProof(
          proofValue: jsonObject['cwt'], proofType: type);
    } else if (type == 'ldp_vp') {
      return CredentialRequestProof(
          proofValue: jsonObject['ldp_vp'], proofType: type);
    } else if (type == 'attestation') {
      // added with draft 15
      return CredentialRequestProof(
          proofValue: jsonObject['attestation'], proofType: type);
    } else {
      jsonObject.remove('proof_type');
      return CredentialRequestProof(proofType: type, proofValue: jsonObject);
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {'proof_type': proofType};
    jsonObject[proofType] = proofValue;

    return jsonObject;
  }
}

class OidCredentialResponseCredentialEntry extends JsonObject {
  dynamic credential;
  OidCredentialResponseCredentialEntry({this.credential});

  factory OidCredentialResponseCredentialEntry.fromJson(dynamic jsonData) {
    if (jsonData is String) {
      return OidCredentialResponseCredentialEntry(credential: jsonData);
    } else if (jsonData is Map) {
      if (jsonData.containsKey('credential')) {
        return OidCredentialResponseCredentialEntry(
            credential: jsonData['credential']);
      } else {
        return OidCredentialResponseCredentialEntry(credential: jsonData);
      }
    } else {
      throw Exception('unsupported format');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    return {'credential': credential};
  }
}

class OidCredentialResponse extends JsonObject {
  dynamic credential;
  // draft 15
  List<OidCredentialResponseCredentialEntry>? credentials;
  String? transactionId,
      cNonce,
      notificationId,

      /// Required in draft 11 and 12, removed in draft 13
      format;
  int? cNonceExpiresIn;

  OidCredentialResponse(
      {this.credential,
      this.credentials,
      this.transactionId,
      this.cNonce,
      this.cNonceExpiresIn,
      this.notificationId,
      this.format});

  OidCredentialResponse.fromJson(dynamic jsonData) {
    var jsonObject = credentialToMap(jsonData);
    var cNonceExpiresTmp = jsonObject['c_nonce_expires_in'];
    credential = jsonObject['credential'];
    credentials = (jsonObject['credentials'] as List?)
        ?.map((e) => OidCredentialResponseCredentialEntry.fromJson(e))
        .toList();
    transactionId = jsonObject['transaction_id'];
    cNonce = jsonObject['c_nonce'];
    cNonceExpiresIn = cNonceExpiresTmp is int? ? cNonceExpiresTmp : null;
    notificationId = jsonObject['notification_id'];
    format = jsonObject['format'];
    if (jsonObject.containsKey('acceptance_token')) {
      transactionId = jsonObject['acceptance_token'];
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (credential != null) {
      jsonObject['credential'] = credential;
    }
    if (credentials != null) {
      jsonObject['credentials'] = credentials!.map((e) => e.toJson()).toList();
    }
    if (format != null) {
      jsonObject['format'] = format;
    }
    if (transactionId != null) {
      jsonObject['transaction_id'] = transactionId;
    }
    if (cNonce != null) {
      jsonObject['c_nonce'] = cNonce;
    }
    if (cNonceExpiresIn != null) {
      jsonObject['c_nonce_expires_in'] = cNonceExpiresIn;
    }
    if (notificationId != null) {
      jsonObject['notification_id'] = notificationId;
    }

    return jsonObject;
  }
}

class OidCredentialFormat {
  static final String sdJwt = 'vc+sd-jwt';
  static final String sdJwtDc = 'dc+sd-jwt';
  static final String msoMdoc = 'mso_mdoc';
  static final String ldpVc = 'ldp_vc';
  static final String jwtVcJson = 'jwt_vc_json';
  static final String jwtVcJsonLd = 'jwt_vc_json-ld';
}

Map<String, dynamic> _parseStuff(Map toParse) {
  Map<String, dynamic> f = {};
  for (var k in toParse.keys) {
    var v = toParse[k];
    if (v is List) {
      var parsed = [];
      for (var e in v) {
        parsed.add(_parseStuff(e));
      }
      f[k] = parsed;
    } else if (v is Map &&
        CredentialSubjectMetadata.isCredentialSubjectMetadata(v)) {
      f[k] = CredentialSubjectMetadata.fromJson(v);
    } else {
      var d = _parseStuff(v);
      f[k] = d;
    }
  }

  return f;
}

Map<String, dynamic> _stuffToJson(Map<String, dynamic> toParse) {
  Map<String, dynamic> f = {};
  for (var k in toParse.keys) {
    var v = toParse[k];
    if (v is List) {
      List parsed = [];
      for (var entry in v) {
        if (entry is CredentialSubjectMetadata) {
          parsed.add(entry.toJson());
        } else {
          parsed.add(_stuffToJson(entry));
        }
      }
      f[k] = parsed;
    } else if (v is CredentialSubjectMetadata) {
      f[k] = v.toJson();
    } else {
      f[k] = _stuffToJson(v);
    }
  }

  return f;
}
