import 'dart:convert';

import 'package:json_path/json_path.dart';
import 'package:uuid/uuid.dart';

import '../../util.dart';
import 'presentation_exchange.dart';

class CredentialManifest implements JsonObject {
  late String id;
  String? name;
  String? description;
  late String specVersion;
  late IssuerProperty issuer;
  late List<OutputDescriptor> outputDescriptor;
  FormatProperty? format;
  PresentationDefinition? presentationDefinition;

  CredentialManifest(
      {String? id,
      this.name,
      this.description,
      this.specVersion =
          'https://identity.foundation/credential-manifest/spec/v1.0.0/',
      required this.issuer,
      required this.outputDescriptor,
      this.format,
      this.presentationDefinition})
      : id = id ?? Uuid().v4();

  CredentialManifest.fromJson(dynamic jsonObject) {
    var map = credentialToMap(jsonObject);
    if (map.containsKey('id')) {
      id = map['id'];
    } else {
      throw Exception('id property needed in Credential manifest');
    }
    name = map['name'];
    description = map['description'];
    specVersion = map['spec_version'] ??
        'https://identity.foundation/credential-manifest/spec/v0.0.0/';
    if (map.containsKey('issuer')) {
      issuer = IssuerProperty.fromJson(map['issuer']);
    } else {
      throw Exception('issuer property needed');
    }
    if (map.containsKey('output_descriptors')) {
      var descriptorList = map['output_descriptors'];
      outputDescriptor = [];
      for (var d in descriptorList) {
        outputDescriptor.add(OutputDescriptor.fromJson(d));
      }
    } else {
      throw Exception('output_descriptors needed in credential Manifest');
    }
    if (map.containsKey('format')) {
      format = FormatProperty.fromJson(map['format']);
    }
    if (map.containsKey('presentation_definition')) {
      presentationDefinition =
          PresentationDefinition.fromJson(map['presentation_definition']);
    }
  }

  @override
  Map<String, dynamic> toJson() {
    var map = {
      'id': id,
      'spec_version': specVersion,
      'issuer': issuer.toJson(),
      'output_descriptors': List.generate(
          outputDescriptor.length, (index) => outputDescriptor[index].toJson())
    };
    if (name != null) {
      map['name'] = name!;
    }
    if (description != null) {
      map['description'] = description!;
    }

    if (format != null) {
      map['format'] = format!.toJson();
    }
    if (presentationDefinition != null) {
      map['presentation_definition'] = presentationDefinition!.toJson();
    }
    return map;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class IssuerProperty implements JsonObject {
  late String id;
  String? name;
  dynamic styles;

  IssuerProperty({String? id, this.name, this.styles})
      : id = id ?? Uuid().v4() {
    if (styles != null) {
      if (styles is! String || styles is! EntityStyles) {
        throw Exception('unexpected Datatype for styles property');
      }
    }
  }

  IssuerProperty.fromJson(dynamic jsonObject) {
    var map = credentialToMap(jsonObject);
    if (map.containsKey('id')) {
      id = map['id'];
    } else {
      throw Exception('id property needed in issuerProperty');
    }

    name = map['name'];

    if (map.containsKey('styles')) {
      var stylesObject = map['styles'];
      if (stylesObject is String) {
        styles = stylesObject;
      } else if (stylesObject is Map) {
        styles = EntityStyles.fromJson(stylesObject);
      } else {
        throw Exception('unknown datatype for styles Property');
      }
    }
  }

  @override
  Map<String, dynamic> toJson() {
    var map = {
      'id': id,
    };
    if (name != null) map['name'] = name!;
    if (styles != null) {
      map['styles'] = styles is String ? styles : styles.toJson();
    }
    return map;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class OutputDescriptor implements JsonObject {
  late String id;
  late String schema;
  String? name;
  String? description;
  dynamic styles;
  DisplayProperty? display;

  OutputDescriptor(
      {String? id,
      required this.schema,
      this.name,
      this.description,
      this.styles,
      this.display})
      : id = id ?? Uuid().v4() {
    if (styles != null) {
      if (styles is! String || styles is! EntityStyles) {
        throw Exception('unexpected Datatype for styles property');
      }
    }
  }

  OutputDescriptor.fromJson(dynamic jsonObject) {
    var map = credentialToMap(jsonObject);
    if (map.containsKey('id')) {
      id = map['id'];
    } else {
      throw Exception('id property needed in output descriptor');
    }
    if (map.containsKey('schema')) {
      schema = map['schema'];
    } else {
      throw Exception('schema property needed in output descriptor');
    }
    name = map['name'];
    description = map['description'];
    if (map.containsKey('styles')) {
      var stylesObject = map['styles'];
      if (stylesObject is String) {
        styles = stylesObject;
      } else if (stylesObject is Map) {
        styles = EntityStyles.fromJson(stylesObject);
      } else {
        throw Exception('unknown datatype for styles Property');
      }
    }

    if (map.containsKey('display')) {
      display = DisplayProperty.fromJson(map['display']);
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> map = {'id': id, 'schema': schema};
    if (name != null) {
      map['name'] = name!;
    }
    if (description != null) {
      map['description'] = description!;
    }
    if (styles != null) {
      map['styles'] = styles is String ? styles : styles.toJson();
    }
    if (display != null) {
      map['display'] = display!.toJson();
    }
    return map;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class DisplayProperty implements JsonObject {
  DisplayMappingObject? title;
  DisplayMappingObject? subtitle;
  DisplayMappingObject? description;
  List<LabeledDisplayMappingObject>? properties;

  DisplayProperty(
      {this.title, this.subtitle, this.description, this.properties});

  DisplayProperty.fromJson(dynamic jsonObject) {
    var map = credentialToMap(jsonObject);
    if (map.containsKey('title')) {
      title = DisplayMappingObject.fromJson(map['title']);
    }
    if (map.containsKey('subtitle')) {
      subtitle = DisplayMappingObject.fromJson(map['subtitle']);
    }
    if (map.containsKey('description')) {
      description = DisplayMappingObject.fromJson(map['description']);
    }
    if (map.containsKey('properties')) {
      List tmp = map['properties'];
      properties =
          tmp.map((e) => LabeledDisplayMappingObject.fromJson(e)).toList();
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> map = {};
    if (title != null) {
      map['title'] = title!.toJson();
    }
    if (subtitle != null) {
      map['subtitle'] = subtitle!.toJson();
    }
    if (description != null) {
      map['description'] = description!.toJson();
    }
    if (properties != null) {
      map['properties'] = properties!.map((e) => e.toJson()).toList();
    }
    return map;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class DisplayMappingObject implements JsonObject {
  List<JsonPath>? path;
  String? text;
  SchemaObject? schema;
  String? fallback;

  DisplayMappingObject({this.text, this.path, this.schema, this.fallback}) {
    if (path == null && text == null) {
      throw Exception('Must contain either pth or text');
    }
  }

  DisplayMappingObject.fromJson(dynamic jsonObject) {
    var map = credentialToMap(jsonObject);
    if (map.containsKey('path')) {
      List tmp = map['path'];
      path = tmp.map((e) => JsonPath(e)).toList();
    }
    if (map.containsKey('schema')) {
      schema = SchemaObject.fromJson(map['schema']);
    }

    text = map['text'];

    fallback = map['fallback'];

    if (path == null && text == null) {
      throw Exception('Must contain either pth or text');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> map = {'path': path.toString()};
    if (text != null) {
      map['text'] = text;
    }
    if (schema != null) {
      map['schema'] = schema!.toJson();
    }
    if (fallback != null) {
      map['fallback'] = fallback!;
    }
    return map;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class LabeledDisplayMappingObject extends DisplayMappingObject {
  late String label;

  LabeledDisplayMappingObject(
      {required this.label,
      required List<JsonPath> path,
      required SchemaObject schema,
      String? fallback})
      : super(path: path, schema: schema, fallback: fallback);

  LabeledDisplayMappingObject.fromJson(dynamic jsonObject)
      : super.fromJson(jsonObject) {
    var map = credentialToMap(jsonObject);
    if (map.containsKey('label')) {
      label = map['label'];
    } else {
      throw Exception('label property needed');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> map = {'label': label};
    map.addAll(super.toJson());
    return map;
  }
}

class SchemaObject implements JsonObject {
  late DIFSchemaType type;
  StringFormat? format;

  SchemaObject({required this.type, this.format});

  SchemaObject.fromJson(dynamic jsonObject) {
    var map = credentialToMap(jsonObject);
    if (map.containsKey('type')) {
      var t = map['type'];
      switch (t) {
        case 'integer':
          type = DIFSchemaType.integer;
          break;
        case 'string':
          type = DIFSchemaType.string;
          break;
        case 'boolean':
          type = DIFSchemaType.boolean;
          break;
        case 'number':
          type = DIFSchemaType.number;
          break;
        default:
          throw Exception('unknown Schema type');
      }
    } else {
      throw Exception('type property needed in schema object');
    }

    if (type == DIFSchemaType.string) {
      if (map.containsKey('format')) {
        var f = map['format'];
        switch (f) {
          case 'date-time':
            format = StringFormat.dateTime;
            break;
          case 'date':
            format = StringFormat.date;
            break;
          case 'time':
            format = StringFormat.time;
            break;
          case 'email':
            format = StringFormat.email;
            break;
          case 'idn-email':
            format = StringFormat.idnEmail;
            break;
          case 'hostname':
            format = StringFormat.hostname;
            break;
          case 'idn-hostname':
            format = StringFormat.idnHostname;
            break;
          case 'ipv4':
            format = StringFormat.ipv4;
            break;
          case 'ipv6':
            format = StringFormat.ipv6;
            break;
          case 'uri':
            format = StringFormat.uri;
            break;
          case 'uri-reference':
            format = StringFormat.uriReference;
            break;
          case 'iri':
            format = StringFormat.iri;
            break;
          case 'iri-reference':
            format = StringFormat.iriReference;
            break;
          default:
            throw Exception('unknown format value');
        }
      }
    }
  }

  @override
  Map<String, dynamic> toJson() {
    var map = {'type': type.value};
    if (format != null) {
      map['format'] = format!.value;
    }
    return map;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class CredentialApplication implements JsonObject {
  late String id;
  late String manifestId;
  late String specVersion;
  late FormatProperty format;
  PresentationSubmission? presentationSubmission;

  CredentialApplication(
      {String? id,
      required this.manifestId,
      this.specVersion =
          'https://identity.foundation/credential-manifest/spec/v1.0.0/',
      required this.format})
      : id = id ?? Uuid().v4();

  CredentialApplication.fromJson(dynamic jsonObject) {
    var map = credentialToMap(jsonObject);
    if (map.containsKey('id')) {
      id = map['id'];
    } else {
      throw Exception('id property needed in Credential application');
    }

    specVersion = map['spec_version'] ??
        'https://identity.foundation/credential-manifest/spec/v0.0.0/';
    if (map.containsKey('manifest_id')) {
      manifestId = map['manifest_id'];
    } else {
      throw Exception('manifest_id property needed in Credential application');
    }

    if (map.containsKey('format')) {
      format = FormatProperty.fromJson(map['format']);
    } else {
      throw Exception('format property needed in credential Application');
    }

    if (map.containsKey('presentation_submission')) {
      presentationSubmission =
          PresentationSubmission.fromJson(map['presentation_submission']);
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> map = {
      'id': id,
      'manifest_id': manifestId,
      'spec_version': specVersion,
      'format': format.toJson()
    };
    if (presentationSubmission != null) {
      map['presentation_submission'] = presentationSubmission!.toJson();
    }
    return map;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class CredentialFulfillment implements JsonObject {
  late String id;
  late String manifestId;
  String? applicationId;
  late List<InputDescriptorMappingObject> descriptorMap;

  CredentialFulfillment(
      {String? id,
      required this.manifestId,
      this.applicationId,
      required this.descriptorMap})
      : id = id ?? Uuid().v4();

  CredentialFulfillment.fromJson(dynamic jsonObject) {
    var map = credentialToMap(jsonObject);
    if (map.containsKey('id')) {
      id = map['id'];
    } else {
      throw Exception('id property needed in credential fulfillment');
    }

    if (map.containsKey('manifest_id')) {
      manifestId = map['manifest_id'];
    } else {
      throw Exception('manifest_id property needed in credential fulfillment');
    }

    applicationId = map['application_id'];

    if (map.containsKey('descriptor_map')) {
      List tmp = map['descriptor_map'];
      descriptorMap =
          tmp.map((e) => InputDescriptorMappingObject.fromJson(e)).toList();
    } else {
      throw Exception(
          'descriptor_map property needed in credential fulfillment');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> map = {'id': id, 'manifest_id': manifestId};
    if (applicationId != null) {
      map['application_id'] = applicationId!;
    }
    map['descriptor_map'] = descriptorMap.map((e) => e.toJson()).toList();
    return map;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class EntityStyles implements JsonObject {
  EntityStylesImage? thumbnail;
  EntityStylesImage? hero;
  String? backgroundColor;
  String? textColor;

  EntityStyles(
      {this.thumbnail, this.hero, this.backgroundColor, this.textColor});

  EntityStyles.fromJson(dynamic jsonObject) {
    var map = credentialToMap(jsonObject);
    if (map.containsKey('thumbnail')) {
      thumbnail = EntityStylesImage.fromJson(map['thumbnail']);
    }
    if (map.containsKey('hero')) {
      hero = EntityStylesImage.fromJson(map['hero']);
    }
    if (map.containsKey('background')) {
      backgroundColor = map['background']['color'];
    }
    if (map.containsKey('text')) {
      textColor = map['text']['color'];
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> map = {};
    if (thumbnail != null) {
      map['thumbnail'] = thumbnail!.toJson();
    }
    if (hero != null) {
      map['hero'] = hero!.toJson();
    }
    if (backgroundColor != null) {
      map['background'] = {'color': backgroundColor};
    }
    if (textColor != null) {
      map['text'] = {'color': textColor};
    }
    return map;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class EntityStylesImage implements JsonObject {
  late String uri;
  String? alt;

  EntityStylesImage({required this.uri, this.alt});

  EntityStylesImage.fromJson(dynamic jsonObject) {
    var map = credentialToMap(jsonObject);

    if (map.containsKey('uri')) {
      uri = map['uri'];
    } else {
      throw Exception('uri property needed in Image object');
    }

    alt = map['alt'];
  }

  @override
  Map<String, dynamic> toJson() {
    var map = {'uri': uri};
    if (alt != null) {
      map['alt'] = alt!;
    }
    return map;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

enum DIFSchemaType {
  string,
  boolean,
  number,
  integer;

  static const Map<DIFSchemaType, String> stringValues = {
    DIFSchemaType.string: 'string',
    DIFSchemaType.integer: 'integer',
    DIFSchemaType.number: 'number',
    DIFSchemaType.boolean: 'boolean'
  };
  String get value => stringValues[this]!;
}

enum StringFormat {
  dateTime,
  date,
  time,
  email,
  idnEmail,
  hostname,
  idnHostname,
  ipv4,
  ipv6,
  uri,
  uriReference,
  iri,
  iriReference;

  static const Map<StringFormat, String> stringValues = {
    StringFormat.dateTime: 'date-time',
    StringFormat.time: 'time',
    StringFormat.date: 'date',
    StringFormat.email: 'email',
    StringFormat.idnEmail: 'idn-email',
    StringFormat.hostname: 'hostname',
    StringFormat.idnHostname: 'idn-hostname',
    StringFormat.ipv4: 'ipv4',
    StringFormat.ipv6: 'ipv6',
    StringFormat.uri: 'uri',
    StringFormat.uriReference: 'uri-reference',
    StringFormat.iri: 'iri',
    StringFormat.iriReference: 'iri-reference'
  };
  String get value => stringValues[this]!;
}
