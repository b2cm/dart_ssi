import 'dart:convert';
import 'dart:io';

import 'package:flutter_ssi_wallet/src/dids/did_key.dart';

import '../util/types.dart';
import '../util/utils.dart';

class DidDocument implements JsonObject {
  List<String>? context;
  late String id;
  List<String>? alsoKnownAs;
  dynamic controller;
  List<VerificationMethod>? verificationMethod;
  List<dynamic>? authentication;
  List<dynamic>? assertionMethod;
  List<dynamic>? keyAgreement;
  List<dynamic>? capabilityInvocation;
  List<dynamic>? capabilityDelegation;
  List<ServiceEndpoint>? service;

  DidDocument(
      {this.context,
      required this.id,
      this.alsoKnownAs,
      this.controller,
      this.verificationMethod,
      this.authentication,
      this.keyAgreement,
      this.service,
      this.assertionMethod,
      this.capabilityDelegation,
      this.capabilityInvocation});

  DidDocument.fromJson(dynamic jsonObject) {
    var document = credentialToMap(jsonObject);
    if (document.containsKey('@context'))
      context = document['@context'].cast<String>();
    if (document.containsKey('id'))
      id = document['id'];
    else
      throw FormatException('id property needed in did document');
    if (document.containsKey('alsoKnownAs'))
      alsoKnownAs = document['alsoKnownAs'].cast<String>();
    controller = document['controller'];
    if (controller != null) if (!(controller is String) ||
        !(controller is List)) {
      throw Exception('controller must be a String or a List');
    }

    if (document.containsKey('verificationMethod')) {
      List tmp = document['verificationMethod'];
      if (tmp.length > 0) {
        verificationMethod = [];
        for (var v in tmp)
          verificationMethod!.add(VerificationMethod.fromJson(v));
      }
    }

    if (document.containsKey('authentication')) {
      List tmp = document['authentication'];
      if (tmp.length > 0) {
        authentication = [];
        for (var v in tmp) {
          if (v is String)
            authentication!.add(v);
          else if (v is Map<String, dynamic>)
            authentication!.add(VerificationMethod.fromJson(v));
          else
            throw FormatException('unknown Datatype');
        }
      }
    }

    if (document.containsKey('keyAgreement')) {
      List tmp = document['keyAgreement'];
      if (tmp.length > 0) {
        keyAgreement = [];
        for (var v in tmp) {
          if (v is String)
            keyAgreement!.add(v);
          else if (v is Map<String, dynamic>)
            keyAgreement!.add(VerificationMethod.fromJson(v));
          else
            throw FormatException('unknown Datatype');
        }
      }
    }

    if (document.containsKey('assertionMethod')) {
      List tmp = document['assertionMethod'];
      if (tmp.length > 0) {
        assertionMethod = [];
        for (var v in tmp) {
          if (v is String)
            assertionMethod!.add(v);
          else if (v is Map<String, dynamic>)
            assertionMethod!.add(VerificationMethod.fromJson(v));
          else
            throw FormatException('unknown Datatype');
        }
      }
    }

    if (document.containsKey('capabilityInvocation')) {
      List tmp = document['capabilityInvocation'];
      if (tmp.length > 0) {
        capabilityInvocation = [];
        for (var v in tmp) {
          if (v is String)
            capabilityInvocation!.add(v);
          else if (v is Map<String, dynamic>)
            capabilityInvocation!.add(VerificationMethod.fromJson(v));
          else
            throw FormatException('unknown Datatype');
        }
      }
    }

    if (document.containsKey('capabilityDelegation')) {
      List tmp = document['capabilityDelegation'];
      if (tmp.length > 0) {
        capabilityDelegation = [];
        for (var v in tmp) {
          if (v is String)
            capabilityDelegation!.add(v);
          else if (v is Map<String, dynamic>)
            capabilityDelegation!.add(VerificationMethod.fromJson(v));
          else
            throw FormatException('unknown Datatype');
        }
      }
    }

    if (document.containsKey('service')) {
      List tmp = document['service'];
      if (tmp.length > 0) {
        service = [];
        for (var v in tmp) service!.add(ServiceEndpoint.fromJson(v));
      }
    }
  }

  DidDocument resolveKeyIds() {
    if (verificationMethod == null || verificationMethod!.length == 0) {
      return this;
    }
    var newDdo = DidDocument(
        id: this.id,
        context: this.context,
        controller: this.controller,
        alsoKnownAs: this.alsoKnownAs,
        service: this.service,
        verificationMethod: this.verificationMethod);
    Map<String, VerificationMethod> veriMap = {};
    for (var v in verificationMethod!) {
      veriMap[v.id] = v;
      if (v.id.contains('#')) {
        var s = v.id.split('#');
        if (s.length == 2) {
          veriMap[s[1]] = v;
        }
      }
    }
    if (assertionMethod != null && assertionMethod!.length > 0)
      newDdo.assertionMethod = _resolveIds(veriMap, assertionMethod!);
    if (keyAgreement != null && keyAgreement!.length > 0)
      newDdo.keyAgreement = _resolveIds(veriMap, keyAgreement!);
    if (authentication != null && authentication!.length > 0)
      newDdo.authentication = _resolveIds(veriMap, authentication!);
    if (capabilityInvocation != null && capabilityInvocation!.length > 0)
      newDdo.capabilityInvocation = _resolveIds(veriMap, capabilityInvocation!);
    if (capabilityDelegation != null && capabilityDelegation!.length > 0)
      newDdo.capabilityDelegation = _resolveIds(veriMap, capabilityDelegation!);
    return newDdo;
  }

  List _resolveIds(Map<String, VerificationMethod> veriMap, List old) {
    List newList = [];
    for (var entry in old) {
      if (entry is VerificationMethod)
        newList.add(entry);
      else if (entry is String) {
        if (veriMap.containsKey(entry)) newList.add(veriMap[entry]);
      } else
        throw Exception(
            'Element $entry has unsupported Datatype ${entry.runtimeType}');
    }
    return newList;
  }

  DidDocument convertAllKeysToJwk() {
    var newDdo = DidDocument(
        id: this.id,
        context: this.context,
        controller: this.controller,
        alsoKnownAs: this.alsoKnownAs,
        service: this.service);

    if (verificationMethod != null && verificationMethod!.length > 0) {
      List<VerificationMethod> newVm = [];
      for (var entry in verificationMethod!) newVm.add(entry.toPublicKeyJwk());
      newDdo.verificationMethod = newVm;
    }
    if (assertionMethod != null && assertionMethod!.length > 0)
      newDdo.assertionMethod = _convertKeys(assertionMethod!);
    if (keyAgreement != null && keyAgreement!.length > 0)
      newDdo.keyAgreement = _convertKeys(keyAgreement!);
    if (authentication != null && authentication!.length > 0)
      newDdo.authentication = _convertKeys(authentication!);
    if (capabilityInvocation != null && capabilityInvocation!.length > 0)
      newDdo.capabilityInvocation = _convertKeys(capabilityInvocation!);
    if (capabilityDelegation != null && capabilityDelegation!.length > 0)
      newDdo.capabilityDelegation = _convertKeys(capabilityDelegation!);
    return newDdo;
  }

  List _convertKeys(List old) {
    List newList = [];
    for (var entry in old) {
      if (entry is VerificationMethod)
        newList.add(entry.toPublicKeyJwk());
      else
        newList.add(entry);
    }
    return newList;
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    if (alsoKnownAs != null) jsonObject['alsoKnownAs'] = alsoKnownAs;
    if (controller != null) jsonObject['controller'] = controller;
    if (verificationMethod != null && verificationMethod!.length > 0) {
      List tmp = [];
      for (var v in verificationMethod!) {
        tmp.add(v.toJson());
      }
      jsonObject['verificationMethod'] = tmp;
    }

    if (authentication != null && authentication!.length > 0) {
      List tmp = [];
      for (var v in authentication!) {
        if (v is VerificationMethod)
          tmp.add(v.toJson());
        else if (v is String)
          tmp.add(v);
        else
          throw FormatException('unknown Datatype');
      }
      jsonObject['authentication'] = tmp;
    }

    if (capabilityDelegation != null && capabilityDelegation!.length > 0) {
      List tmp = [];
      for (var v in capabilityDelegation!) {
        if (v is VerificationMethod)
          tmp.add(v.toJson());
        else if (v is String)
          tmp.add(v);
        else
          throw FormatException('unknown Datatype');
      }
      jsonObject['capabilityDelegation'] = tmp;
    }

    if (capabilityInvocation != null && capabilityInvocation!.length > 0) {
      List tmp = [];
      for (var v in capabilityInvocation!) {
        if (v is VerificationMethod)
          tmp.add(v.toJson());
        else if (v is String)
          tmp.add(v);
        else
          throw FormatException('unknown Datatype');
      }
      jsonObject['capabilityInvocation'] = tmp;
    }

    if (keyAgreement != null && keyAgreement!.length > 0) {
      List tmp = [];
      for (var v in keyAgreement!) {
        if (v is VerificationMethod)
          tmp.add(v.toJson());
        else if (v is String)
          tmp.add(v);
        else
          throw FormatException('unknown Datatype');
      }
      jsonObject['keyAgreement'] = tmp;
    }

    if (assertionMethod != null && assertionMethod!.length > 0) {
      List tmp = [];
      for (var v in assertionMethod!) {
        if (v is VerificationMethod)
          tmp.add(v.toJson());
        else if (v is String)
          tmp.add(v);
        else
          throw FormatException('unknown Datatype');
      }
      jsonObject['assertionMethod'] = tmp;
    }

    if (service != null && service!.length > 0) {
      List tmp = [];
      for (var v in service!) {
        tmp.add(v.toJson());
      }
      jsonObject['verificationMethod'] = tmp;
    }

    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class VerificationMethod implements JsonObject {
  late String id;
  late String controller;
  late String type;
  Map<String, dynamic>? publicKeyJwk;
  String? publicKeyMultibase;

  VerificationMethod(
      {required this.id,
      required this.controller,
      required this.type,
      this.publicKeyJwk,
      this.publicKeyMultibase}) {
    if (publicKeyJwk == null && publicKeyMultibase == null)
      throw Exception(
          'Verification Method must have an entry for a public key');
  }

  VerificationMethod.fromJson(dynamic jsonObject) {
    var method = credentialToMap(jsonObject);
    if (method.containsKey('id'))
      id = method['id'];
    else
      throw FormatException('id property is needed in Verification Method');
    if (method.containsKey('type'))
      type = method['type'];
    else
      throw FormatException('type property is needed in Verification Method');
    if (method.containsKey('controller'))
      controller = method['controller'];
    else
      throw FormatException(
          'controller property is needed in Verification Method');
    publicKeyJwk = method['publicKeyJwk'];
    publicKeyMultibase = method['publicKeyMultibase'];

    if (publicKeyJwk == null && publicKeyMultibase == null)
      throw Exception(
          'Verification Method must have an entry for a public key');
  }

  VerificationMethod toPublicKeyJwk() {
    if (publicKeyMultibase != null)
      return VerificationMethod(
          id: id,
          controller: controller,
          type: 'JsonWebKey2020',
          publicKeyJwk: multibaseKeyToJwk(publicKeyMultibase!));
    else if (publicKeyJwk != null)
      return this;
    else
      throw Exception('Cant find key in this Verification Method');
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    jsonObject['controller'] = controller;
    jsonObject['type'] = type;
    if (publicKeyMultibase != null)
      jsonObject['publicKeyMultibase'] = publicKeyMultibase;
    if (publicKeyJwk != null) jsonObject['publicKeyJwk'] = publicKeyJwk;
    return jsonObject;
  }

  String toString() {
    return jsonEncode(toJson());
  }
}

class ServiceEndpoint implements JsonObject {
  late String id;
  late String type;
  late dynamic serviceEndpoint;

  ServiceEndpoint(
      {required this.id, required this.type, required this.serviceEndpoint});

  ServiceEndpoint.fromJson(dynamic jsonObject) {
    var se = credentialToMap(jsonObject);
    if (se.containsKey(['id']))
      id = se['id'];
    else
      throw FormatException('id property is needed in serviceEndpoint');
    if (se.containsKey('type'))
      type = se['type'];
    else
      throw FormatException('format property is needed in serviceEndpoint');
    if (se.containsKey('serviceEndpoint'))
      serviceEndpoint = se['serviceEndpoint'];
    else
      throw FormatException(
          'serviceEndpoint property is needed in serviceEndpoint');
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    jsonObject['type'] = type;
    jsonObject['serviceEndpoint'] = serviceEndpoint;
    return jsonObject;
  }

  String toString() {
    return jsonEncode(toJson());
  }
}

Future<DidDocument> resolveDidDocument(String did,
    [String? resolverAddress]) async {
  if (did.startsWith('did:key:z6Mk'))
    return resolveDidKey(did);
  else {
    if (resolverAddress == null)
      throw Exception(
          'The did con only be resolved using universal resolver, therefore the resolver address is required');
    try {
      var client = await HttpClient()
          .getUrl(Uri.parse('$resolverAddress/1.0/identifiers/$did'))
          .timeout(Duration(seconds: 30));
      var res = await client.close();
      if (res.statusCode == 200) {
        var contents = StringBuffer();
        await for (var data in res.transform(utf8.decoder)) {
          contents.write(data);
        }
        var didResolution = jsonDecode(contents.toString());
        return DidDocument.fromJson(didResolution['didDocument']);
      } else
        throw Exception('Bad status code ${res.statusCode}');
    } catch (e) {
      throw Exception('Something went wrong during resolving: $e');
    }
  }
}
