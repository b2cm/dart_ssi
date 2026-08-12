import 'dart:convert';

import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/oid.dart';
import 'package:dart_ssi/src/util/types.dart';
import 'package:dart_ssi/src/util/utils.dart';

class RequestObject extends JsonObject {
  String? responseType;
  String? responseUri;
  String? clientId;
  String? responseMode;
  String? redirectUri;
  String? nonce, state;
  String? clientMetaDataUri;
  PresentationDefinition? presentationDefinition;
  String? presentationDefinitionUri;
  DcqlQuery? dcqlQuery;
  ClientMetaData? clientMetaData;
  List<String>? transactionData;

  RequestObject(
      {this.clientId,
      this.responseUri,
      this.nonce,
      this.state,
      this.redirectUri,
      this.responseMode = 'fragment',
      this.responseType,
      this.presentationDefinition,
      this.clientMetaData,
      this.clientMetaDataUri,
      this.dcqlQuery,
      this.presentationDefinitionUri,
      this.transactionData});

  RequestObject.fromJson(dynamic data) {
    var jsonObject = credentialToMap(data);

    responseType = jsonObject['response_type'];
    clientId = jsonObject['client_id'];
    responseMode = jsonObject['response_mode'] ?? 'fragment';
    redirectUri = jsonObject['redirect_uri'];
    nonce = jsonObject['nonce'];
    presentationDefinitionUri = jsonObject['presentation_definition_uri'];
    clientMetaDataUri = jsonObject['client_metadata_uri'];
    responseUri = jsonObject['response_uri'];
    state = jsonObject['state'];

    if (jsonObject.containsKey('presentation_definition')) {
      presentationDefinition = PresentationDefinition.fromJson(
          jsonObject['presentation_definition']);
    }

    if (jsonObject.containsKey('dcql_query')) {
      dcqlQuery = DcqlQuery.fromJson(jsonObject['dcql_query']);
    }

    if (jsonObject.containsKey('client_metadata')) {
      clientMetaData = ClientMetaData.fromJson(jsonObject['client_metadata']);
    }

    if (jsonObject.containsKey('transaction_data')) {
      var raw = jsonObject['transaction_data'];
      List td;
      if (raw is String) {
        td = jsonDecode(raw) as List;
      } else {
        td = raw;
      }
      transactionData = td.cast<String>();
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
    if (responseUri != null) {
      jsonObject['response_uri'] = responseUri;
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
    if (state != null) {
      jsonObject['state'] = state;
    }
    if (presentationDefinitionUri != null) {
      jsonObject['presentation_definition_uri'] = presentationDefinitionUri;
    }
    if (presentationDefinition != null) {
      jsonObject['presentation_definition'] =
          presentationDefinition!.toString();
    }
    if (dcqlQuery != null) {
      jsonObject['dcql_query'] = dcqlQuery!.toString();
    }

    if (clientMetaData != null) {
      jsonObject['client_metadata'] = clientMetaData!.toString();
    }
    if (clientMetaDataUri != null) {
      jsonObject['client_metadata_uri'] = clientMetaDataUri;
    }
    if (transactionData != null) {
      jsonObject['transaction_data'] = jsonEncode(transactionData);
    }
    return jsonObject;
  }
}

class ClientMetaData extends JsonObject {
  List<Map<String, dynamic>>? jwks;
  String? jwksUri;
  String? authEncryptedResponseAlg,
      authEncryptedResponseEnc,
      authSignedResponseAlg;
  List<String>? encryptedResponseEncValuesSupported;
  VpFormats? vpFormats;

  ClientMetaData(
      {this.jwks,
      this.jwksUri,
      this.vpFormats,
      this.authEncryptedResponseAlg,
      this.authEncryptedResponseEnc,
      this.authSignedResponseAlg,
      this.encryptedResponseEncValuesSupported});

  ClientMetaData.fromJson(dynamic data) {
    var jsonData = credentialToMap(data);
    if (jsonData.containsKey('jwks')) {
      var tmp = jsonData['jwks'] as Map;
      var keys = (tmp['keys'] as List).cast<Map>();
      jwks = keys
          .map((e) => e.map((key, value) => MapEntry(key as String, value)))
          .toList();
    }

    if (jsonData.containsKey('jwks_uri')) {
      jwksUri = jsonData['jwks_uri'];
    }

    if (jsonData.containsKey('authorization_encrypted_response_alg')) {
      authEncryptedResponseAlg =
          jsonData['authorization_encrypted_response_alg'];
    }

    if (jsonData.containsKey('authorization_encrypted_response_enc')) {
      authEncryptedResponseEnc =
          jsonData['authorization_encrypted_response_enc'];
    }

    if (jsonData.containsKey('authorization_signed_response_alg')) {
      authSignedResponseAlg = jsonData['authorization_signed_response_alg'];
    }

    if (jsonData.containsKey('vp_formats')) {
      vpFormats = VpFormats.fromJson(jsonData['vp_formats']);
    }

    if (jsonData.containsKey('vp_formats_supported')) {
      vpFormats = VpFormats.fromJson(jsonData['vp_formats_supported']);
    }

    if (jsonData.containsKey('encrypted_response_enc_values_supported')) {
      encryptedResponseEncValuesSupported =
          (jsonData['encrypted_response_enc_values_supported'] as List)
              .cast<String>();
    }
  }
  @override
  Map<String, dynamic> toJson() {
    var json = <String, dynamic>{};

    if (jwks != null) {
      json['jwks'] = {'keys': jwks};
    }
    if (jwksUri != null) {
      json['jwks_uri'] = jwksUri;
    }

    if (authEncryptedResponseEnc != null) {
      json['authorization_encrypted_response_enc'] = authEncryptedResponseEnc;
    }
    if (authEncryptedResponseAlg != null) {
      json['authorization_encrypted_response_alg'] = authEncryptedResponseAlg;
    }
    if (authSignedResponseAlg != null) {
      json['authorization_signed_response_alg'] = authSignedResponseAlg;
    }

    if (vpFormats != null) {
      json['vp_formats_supported'] = vpFormats!.toJson();
    }

    if (encryptedResponseEncValuesSupported != null) {
      json['encrypted_response_enc_values_supported'] =
          encryptedResponseEncValuesSupported;
    }

    return json;
  }
}

class VpFormats extends JsonObject {
  VpFormatLdp? ldp;
  VpFormatSdJwt? sdJwt;
  VpFormatMsoMdoc? msoMdoc;
  VpFormatJwtVcJson? jwtVcJson;
  VpFormatJwtVcJson? jwtVcJsonLd;

  VpFormats(
      {this.ldp, this.sdJwt, this.msoMdoc, this.jwtVcJson, this.jwtVcJsonLd});

  factory VpFormats.fromJson(dynamic jsonData) {
    var json = credentialToMap(jsonData);
    return VpFormats(
        sdJwt: json.containsKey(OidCredentialFormat.sdJwtDc)
            ? VpFormatSdJwt.fromJson(json[OidCredentialFormat.sdJwtDc])
            : json.containsKey(OidCredentialFormat.sdJwt)
                ? VpFormatSdJwt.fromJson(json[OidCredentialFormat.sdJwt])
                : null,
        msoMdoc: json.containsKey(OidCredentialFormat.msoMdoc)
            ? VpFormatMsoMdoc.fromJson(json[OidCredentialFormat.msoMdoc])
            : null,
        jwtVcJson: json.containsKey(OidCredentialFormat.jwtVcJson)
            ? VpFormatJwtVcJson.fromJson(json[OidCredentialFormat.jwtVcJson])
            : null,
        jwtVcJsonLd: json.containsKey(OidCredentialFormat.jwtVcJsonLd)
            ? VpFormatJwtVcJson.fromJson(json[OidCredentialFormat.jwtVcJsonLd])
            : null,
        ldp: json.containsKey(OidCredentialFormat.ldpVc)
            ? VpFormatLdp.fromJson(json[OidCredentialFormat.ldpVc])
            : null);
  }

  @override
  Map<String, dynamic> toJson() {
    return {
      if (ldp != null) OidCredentialFormat.ldpVc: ldp!.toJson(),
      if (sdJwt != null) OidCredentialFormat.sdJwtDc: sdJwt!.toJson(),
      if (msoMdoc != null) OidCredentialFormat.msoMdoc: msoMdoc!.toJson(),
      if (jwtVcJson != null) OidCredentialFormat.jwtVcJson: jwtVcJson!.toJson(),
      if (jwtVcJsonLd != null)
        OidCredentialFormat.jwtVcJsonLd: jwtVcJsonLd!.toJson()
    };
  }
}

class VpFormatJwtVcJson extends JsonObject {
  List<String>? algValues;

  VpFormatJwtVcJson({this.algValues});

  factory VpFormatJwtVcJson.fromJson(dynamic jsonData) {
    var json = credentialToMap(jsonData);

    return VpFormatJwtVcJson(
        algValues: (json['alg_values'] as List<dynamic>?)
            ?.map((e) => e as String)
            .toList());
  }

  @override
  Map<String, dynamic> toJson() {
    return <String, dynamic>{if (algValues != null) 'alg_values': algValues};
  }
}

class VpFormatLdp extends JsonObject {
  List<String>? proofTypeValues;
  List<String>? cryptosuiteValues;

  VpFormatLdp({this.proofTypeValues, this.cryptosuiteValues});

  factory VpFormatLdp.fromJson(dynamic jsonData) {
    var json = credentialToMap(jsonData);
    return VpFormatLdp(
        proofTypeValues: (json['proof_type_values'] as List<dynamic>?)
            ?.map((e) => e as String)
            .toList(),
        cryptosuiteValues: (json['cryptosuite_values'] as List<dynamic>?)
            ?.map((e) => e as String)
            .toList());
  }

  @override
  Map<String, dynamic> toJson() {
    return {
      if (proofTypeValues != null) 'proof_type_values': proofTypeValues,
      if (cryptosuiteValues != null) 'cryptosuite_values': cryptosuiteValues
    };
  }
}

class VpFormatMsoMdoc extends JsonObject {
  List<int>? issuerAuthAlgValues;
  List<int>? deviceAuthAlgValues;

  VpFormatMsoMdoc({this.issuerAuthAlgValues, this.deviceAuthAlgValues});

  factory VpFormatMsoMdoc.fromJson(dynamic jsonData) {
    var json = credentialToMap(jsonData);
    return VpFormatMsoMdoc(
        issuerAuthAlgValues: (json['issuerauth_alg_values'] as List<dynamic>?)
            ?.map((e) => e as int)
            .toList(),
        deviceAuthAlgValues: (json['deviceauth_alg_values'] as List<dynamic>?)
            ?.map((e) => e as int)
            .toList());
  }

  @override
  Map<String, dynamic> toJson() {
    return {
      if (issuerAuthAlgValues != null)
        'issuerauth_alg_values': issuerAuthAlgValues,
      if (deviceAuthAlgValues != null)
        'deviceauth_alg_values': deviceAuthAlgValues
    };
  }
}

class VpFormatSdJwt extends JsonObject {
  List<String>? sdJwtAlgValues;
  List<String>? kbJwtAlgValues;

  VpFormatSdJwt({this.sdJwtAlgValues, this.kbJwtAlgValues});

  factory VpFormatSdJwt.fromJson(dynamic jsonData) {
    var json = credentialToMap(jsonData);
    return VpFormatSdJwt(
        sdJwtAlgValues: (json['sd-jwt_alg_values'] as List<dynamic>?)
            ?.map((e) => e as String)
            .toList(),
        kbJwtAlgValues: (json['kb-jwt_alg_values'] as List<dynamic>?)
            ?.map((e) => e as String)
            .toList());
  }

  @override
  Map<String, dynamic> toJson() {
    return {
      if (sdJwtAlgValues != null) 'sd-jwt_alg_values': sdJwtAlgValues,
      if (kbJwtAlgValues != null) 'kb-jwt_alg_values': kbJwtAlgValues
    };
  }
}

class AuthorizationServerMetadata extends JsonObject {
  // Basic parameters from RFC 8414
  final String? issuer;
  final String? authorizationEndpoint;
  final String? tokenEndpoint;
  final String? jwksUri;
  final String? registrationEndpoint;
  final List<String>? scopesSupported;
  final List<String>? responseTypesSupported;
  final List<String>? responseModesSupported;
  final List<String>? grantTypesSupported;
  final List<String>? tokenEndpointAuthMethodsSupported;
  final List<String>? tokenEndpointAuthSigningAlgValuesSupported;
  final String? serviceDocumentation;
  final List<String>? uiLocalesSupported;
  final String? opPolicyUri;
  final String? opTosUri;
  final String? revocationEndpoint;
  final List<String>? revocationEndpointAuthMethodsSupported;
  final List<String>? revocationEndpointAuthSigningAlgValuesSupported;
  final String? introspectionEndpoint;
  final List<String>? introspectionEndpointAuthMethodsSupported;
  final List<String>? introspectionEndpointAuthSigningAlgValuesSupported;
  final List<String>? codeChallengeMethodsSupported;
  // Additional parameters from rfc 9126 Pushed Authorization Request
  final String? pushedAuthorizationRequestEndpoint;
  final bool? requirePushedAuthorizationRequests;
  // Additional parameters from Oid4VP
  final VpFormats? vpFormatsSupported;
  final List<String>? clientIdPrefixesSupported;

  AuthorizationServerMetadata({
    this.issuer,
    this.authorizationEndpoint,
    this.tokenEndpoint,
    this.jwksUri,
    this.registrationEndpoint,
    this.scopesSupported,
    this.responseTypesSupported,
    this.responseModesSupported,
    this.grantTypesSupported,
    this.tokenEndpointAuthMethodsSupported,
    this.tokenEndpointAuthSigningAlgValuesSupported,
    this.serviceDocumentation,
    this.uiLocalesSupported,
    this.opPolicyUri,
    this.opTosUri,
    this.revocationEndpoint,
    this.revocationEndpointAuthMethodsSupported,
    this.revocationEndpointAuthSigningAlgValuesSupported,
    this.introspectionEndpoint,
    this.introspectionEndpointAuthMethodsSupported,
    this.introspectionEndpointAuthSigningAlgValuesSupported,
    this.codeChallengeMethodsSupported,
    this.pushedAuthorizationRequestEndpoint,
    this.requirePushedAuthorizationRequests,
    this.vpFormatsSupported,
    this.clientIdPrefixesSupported,
  });

  factory AuthorizationServerMetadata.fromJson(dynamic data) {
    var json = credentialToMap(data);
    return AuthorizationServerMetadata(
      issuer: json['issuer'] as String,
      authorizationEndpoint: json['authorization_endpoint'] as String,
      tokenEndpoint: json['token_endpoint'] as String,
      jwksUri: json['jwks_uri'] as String,
      registrationEndpoint: json['registration_endpoint'] as String?,
      scopesSupported: (json['scopes_supported'] as List<dynamic>?)
          ?.map((e) => e as String)
          .toList(),
      responseTypesSupported:
          (json['response_types_supported'] as List<dynamic>?)
              ?.map((e) => e as String)
              .toList(),
      responseModesSupported:
          (json['response_modes_supported'] as List<dynamic>?)
              ?.map((e) => e as String)
              .toList(),
      grantTypesSupported: (json['grant_types_supported'] as List<dynamic>?)
          ?.map((e) => e as String)
          .toList(),
      tokenEndpointAuthMethodsSupported:
          (json['token_endpoint_auth_methods_supported'] as List<dynamic>?)
              ?.map((e) => e as String)
              .toList(),
      tokenEndpointAuthSigningAlgValuesSupported:
          (json['token_endpoint_auth_signing_alg_values_supported']
                  as List<dynamic>?)
              ?.map((e) => e as String)
              .toList(),
      serviceDocumentation: json['service_documentation'],
      uiLocalesSupported: (json['ui_locales_supported'] as List<dynamic>?)
          ?.map((e) => e as String)
          .toList(),
      opPolicyUri: json['op_policy_uri'],
      opTosUri: json['op_tos_uri'],
      revocationEndpoint: json['revocation_endpoint'],
      revocationEndpointAuthMethodsSupported:
          (json['revocation_endpoint_auth_methods_supported'] as List<dynamic>?)
              ?.map((e) => e as String)
              .toList(),
      revocationEndpointAuthSigningAlgValuesSupported:
          (json['revocation_endpoint_auth_signing_alg_values_supported']
                  as List<dynamic>?)
              ?.map((e) => e as String)
              .toList(),
      introspectionEndpoint: json['introspection_endpoint'],
      introspectionEndpointAuthMethodsSupported:
          (json['introspection_endpoint_auth_methods_supported']
                  as List<dynamic>?)
              ?.map((e) => e as String)
              .toList(),
      introspectionEndpointAuthSigningAlgValuesSupported:
          (json['introspection_endpoint_auth_signing_alg_values_supported']
                  as List<dynamic>?)
              ?.map((e) => e as String)
              .toList(),
      codeChallengeMethodsSupported:
          (json['code_challenge_methods_supported'] as List<dynamic>?)
              ?.map((e) => e as String)
              .toList(),
      pushedAuthorizationRequestEndpoint:
          json['pushed_authorization_request_endpoint'],
      requirePushedAuthorizationRequests:
          json['require_pushed_authorization_requests'],
      vpFormatsSupported: json.containsKey('vp_formats_supported')
          ? VpFormats.fromJson(json['vp_formats_supported'])
          : null,
      clientIdPrefixesSupported:
          (json['client_id_prefixes_supported'] as List<dynamic>?)
              ?.map((e) => e as String)
              .toList(),
    );
  }

  @override
  Map<String, dynamic> toJson() {
    return {
      if (issuer != null) 'issuer': issuer,
      if (authorizationEndpoint != null)
        'authorization_endpoint': authorizationEndpoint,
      if (tokenEndpoint != null) 'token_endpoint': tokenEndpoint,
      if (jwksUri != null) 'jwks_uri': jwksUri,
      if (registrationEndpoint != null)
        'registration_endpoint': registrationEndpoint,
      if (scopesSupported != null) 'scopes_supported': scopesSupported,
      if (responseTypesSupported != null)
        'response_types_supported': responseTypesSupported,
      if (responseModesSupported != null)
        'response_modes_supported': responseModesSupported,
      if (grantTypesSupported != null)
        'grant_types_supported': grantTypesSupported,
      if (tokenEndpointAuthMethodsSupported != null)
        'token_endpoint_auth_methods_supported':
            tokenEndpointAuthMethodsSupported,
      if (tokenEndpointAuthSigningAlgValuesSupported != null)
        'token_endpoint_auth_signing_alg_values_supported':
            tokenEndpointAuthSigningAlgValuesSupported,
      if (serviceDocumentation != null)
        'service_documentation': serviceDocumentation,
      if (uiLocalesSupported != null)
        'ui_locales_supported': uiLocalesSupported,
      if (opPolicyUri != null) 'op_policy_uri': opPolicyUri,
      if (opTosUri != null) 'op_tos_uri': opTosUri,
      if (revocationEndpoint != null) 'revocation_endpoint': revocationEndpoint,
      if (revocationEndpointAuthMethodsSupported != null)
        'revocation_endpoint_auth_methods_supported':
            revocationEndpointAuthMethodsSupported,
      if (revocationEndpointAuthSigningAlgValuesSupported != null)
        'revocation_endpoint_auth_signing_alg_values_supported':
            revocationEndpointAuthSigningAlgValuesSupported,
      if (introspectionEndpoint != null)
        'introspection_endpoint': introspectionEndpoint,
      if (introspectionEndpointAuthMethodsSupported != null)
        'introspection_endpoint_auth_methods_supported':
            introspectionEndpointAuthMethodsSupported,
      if (introspectionEndpointAuthSigningAlgValuesSupported != null)
        'introspection_endpoint_auth_signing_alg_values_supported':
            introspectionEndpointAuthSigningAlgValuesSupported,
      if (codeChallengeMethodsSupported != null)
        'code_challenge_methods_supported': codeChallengeMethodsSupported,
      if (pushedAuthorizationRequestEndpoint != null)
        'pushed_authorization_request_endpoint':
            pushedAuthorizationRequestEndpoint,
      if (requirePushedAuthorizationRequests != null)
        'require_pushed_authorization_requests':
            requirePushedAuthorizationRequests,
      if (vpFormatsSupported != null)
        'vp_formats_supported': vpFormatsSupported!.toJson(),
      if (clientIdPrefixesSupported != null)
        'client_id_prefixes_supported': clientIdPrefixesSupported
    };
  }

  String toUrlEncodedString() {
    final Map<String, dynamic> json = toJson();
    return json.entries.map((entry) {
      final key = Uri.encodeQueryComponent(entry.key);
      final value = entry.value is List
          ? (entry.value as List)
              .map((v) => Uri.encodeQueryComponent(v.toString()))
              .join(',')
          : Uri.encodeQueryComponent(entry.value.toString());
      return '$key=$value';
    }).join('&');
  }
}
