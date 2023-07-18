import 'dart:convert';

import 'package:dart_ssi/credentials.dart';
import 'package:json_path/json_path.dart';
import 'package:json_schema/json_schema.dart';
import 'package:uuid/uuid.dart';

import '../util/types.dart';
import '../util/utils.dart';

class PresentationDefinition implements JsonObject {
  late String id;
  late List<InputDescriptor> inputDescriptors;
  String? name;
  String? purpose;
  FormatProperty? format;
  List<SubmissionRequirement>? submissionRequirement;

  PresentationDefinition(
      {String? id,
      required this.inputDescriptors,
      this.name,
      this.purpose,
      this.format,
      this.submissionRequirement})
      : id = id ?? Uuid().v4();

  PresentationDefinition.fromJson(dynamic presentationDefinitionJson) {
    var definition = credentialToMap(presentationDefinitionJson);
    if (definition.containsKey('presentation_definition')) {
      definition = definition['presentation_definition'];
    }
    if (definition.containsKey('id')) {
      id = definition['id'];
    } else {
      throw FormatException('id property required in presentation definition');
    }

    if (definition.containsKey('input_descriptors')) {
      List tmp = definition['input_descriptors'];
      inputDescriptors = [];
      if (tmp.isNotEmpty) {
        for (var i in tmp) {
          inputDescriptors.add(InputDescriptor.fromJson(i));
        }
      }
    } else {
      throw FormatException(
          'input_descriptors property is required in presentation definition');
    }

    if (definition.containsKey('name')) name = definition['name'];
    if (definition.containsKey('purpose')) purpose = definition['purpose'];
    if (definition.containsKey('format')) {
      format = FormatProperty.fromJson(definition['format']);
    }

    if (definition.containsKey('submission_requirements')) {
      List tmp = definition['submission_requirements'];
      if (tmp.isNotEmpty) {
        submissionRequirement = [];
        for (var s in tmp) {
          submissionRequirement!.add(SubmissionRequirement.fromJson(s));
        }
      }
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    List input = [];
    for (var des in inputDescriptors) {
      input.add(des.toJson());
    }
    jsonObject['input_descriptors'] = input;
    if (name != null) jsonObject['name'] = name;
    if (purpose != null) jsonObject['purpose'] = purpose;
    if (format != null) jsonObject['format'] = format!.toJson();
    if (submissionRequirement != null) {
      List sr = [];
      for (var s in submissionRequirement!) {
        sr.add(s.toJson());
      }
      jsonObject['submission_requirements'] = sr;
    }
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class InputDescriptor implements JsonObject {
  late String id;
  String? name;
  String? purpose;
  FormatProperty? format;
  InputDescriptorConstraints? constraints;
  List<String>? group;

  InputDescriptor(
      {String? id,
      this.name,
      this.purpose,
      this.format,
      this.constraints,
      this.group})
      : id = id ?? Uuid().v4();

  InputDescriptor.fromJson(dynamic inputDescriptorJson) {
    var input = credentialToMap(inputDescriptorJson);
    if (input.containsKey('id')) {
      id = input['id'];
    } else {
      throw FormatException('Input descriptor needs id property');
    }

    if (input.containsKey('name')) name = input['name'];
    if (input.containsKey('purpose')) purpose = input['purpose'];
    if (input.containsKey('constraints')) {
      constraints = InputDescriptorConstraints.fromJson(input['constraints']);
    }
    if (input.containsKey('group')) group = input['group'].cast<String>();
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    if (name != null) jsonObject['name'] = name;
    if (purpose != null) jsonObject['purpose'] = purpose;
    if (format != null) jsonObject['format'] = format!.toJson();
    if (constraints != null) jsonObject['constraints'] = constraints!.toJson();
    if (group != null) jsonObject['group'] = group;
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class InputDescriptorConstraints implements JsonObject {
  List<InputDescriptorField>? fields;
  Limiting? limitDisclosure;

  /// Either `required` or `preferred`.
  ///
  /// - `required`: This indicates that the processing entity MUST submit a response that has been self-attested.
  /// - `preferred`: This indicates that it is RECOMMENDED that the processing entity submit a response that has been self-attested.
  Limiting? subjectIsIssuer;

  /// The is_holder property would be used by a Verifier to require that certain inputs be provided by a certain Subject
  HolderSubjectConstraint? isHolder;

  /// The same_subject property would be used by a Verifier to require that certain provided inputs be about the same Subject
  HolderSubjectConstraint? sameSubject;
  StatusObject? statuses;

  InputDescriptorConstraints(
      {this.fields,
      this.limitDisclosure,
      this.subjectIsIssuer,
      this.isHolder,
      this.sameSubject,
      this.statuses});

  InputDescriptorConstraints.fromJson(dynamic constraintsJson) {
    var constraints = credentialToMap(constraintsJson);
    if (constraints.containsKey('limit_disclosure')) {
      var ld = constraints['limit_disclosure'];
      if (ld == 'required') {
        limitDisclosure = Limiting.required;
      } else if (ld == 'preferred') {
        limitDisclosure = Limiting.preferred;
      } else {
        throw Exception('Unknown value in limit_disclosure');
      }
    }

    if (constraints.containsKey('fields')) {
      fields = [];
      List tmp = constraints['fields'];
      if (tmp.isNotEmpty) {
        for (var f in tmp) {
          fields!.add(InputDescriptorField.fromJson(f));
        }
      }
    }

    if (constraints.containsKey('subject_is_issuer')) {
      String sii = constraints['subject_is_issuer'];
      if (sii == 'required') {
        subjectIsIssuer = Limiting.required;
      } else if (sii == 'preferred') {
        subjectIsIssuer = Limiting.preferred;
      } else {
        throw Exception('Unknown value in limit_disclosure');
      }
    }

    if (constraints.containsKey('is_holder')) {
      isHolder = HolderSubjectConstraint.fromJson(constraints['is_holder']);
    }

    if (constraints.containsKey('same_subject')) {
      sameSubject =
          HolderSubjectConstraint.fromJson(constraints['same_subject']);
    }

    if (constraints.containsKey('statuses')) {
      statuses = StatusObject.fromJson(constraints['status']);
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (fields != null) {
      List field = [];
      for (var f in fields!) {
        field.add(f.toJson());
      }
      jsonObject['fields'] = field;
    }

    if (limitDisclosure != null) {
      if (limitDisclosure == Limiting.preferred) {
        jsonObject['limit_disclosure'] = 'preferred';
      } else {
        jsonObject['limit_disclosure'] = 'required';
      }
    }

    if (subjectIsIssuer != null) {
      if (subjectIsIssuer == Limiting.preferred) {
        jsonObject['subject_is_issuer'] = 'preferred';
      } else {
        jsonObject['subject_is_issuer'] = 'required';
      }
    }

    if (isHolder != null) jsonObject['is_holder'] = isHolder!.toJson();

    if (sameSubject != null) jsonObject['same_subject'] = sameSubject!.toJson();

    if (statuses != null) jsonObject['statuses'] = statuses!.toJson();

    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class InputDescriptorField implements JsonObject {
  late List<JsonPath> path;
  String? id;
  String? purpose;
  String? name;
  JsonSchema? filter;
  bool? optional;

  /// Either `required` or `preferred`.
  ///
  /// - `required`: This indicates that the returned value MUST be the boolean result of applying the value of the filter property to the result of evaluating the path property.
  /// - `preferred`: This indicates that the returned value SHOULD be the boolean result of applying the value of the filter property to the result of evaluating the path property.
  Limiting? predicate;

  InputDescriptorField(
      {required this.path,
      this.id,
      this.purpose,
      this.name,
      this.filter,
      this.optional,
      this.predicate});

  InputDescriptorField.fromJson(dynamic fieldJson) {
    var field = credentialToMap(fieldJson);
    if (field.containsKey('path')) {
      List pathString = field['path'];
      path = [];
      for (var p in pathString) {
        path.add(JsonPath(p));
      }
    } else {
      throw FormatException('InputDescriptor need path property');
    }

    if (field.containsKey('id')) id = field['id'];
    if (field.containsKey('purpose')) purpose = field['purpose'];
    if (field.containsKey('name')) name = field['name'];
    if (field.containsKey('filter')) {
      filter = JsonSchema.create(field['filter']);
    }
    if (field.containsKey('optional')) optional = field['optional'];
    if (field.containsKey('predicate')) {
      String p = field['predicate'];
      if (p == 'preferred') {
        predicate = Limiting.preferred;
      } else if (p == 'required') {
        predicate = Limiting.required;
      } else {
        throw Exception('Unknown value for predicate');
      }
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    List<String> paths = [];
    for (var p in path) {
      paths.add(p.toString());
    }
    jsonObject['path'] = paths;

    if (id != null) jsonObject['id'] = id;
    if (purpose != null) jsonObject['purpose'] = purpose;
    if (name != null) jsonObject['name'] = name;
    if (optional != null) jsonObject['optional'] = optional;

    if (filter != null) jsonObject['filter'] = jsonDecode(filter!.toJson());
    if (predicate != null) {
      if (predicate == Limiting.required) {
        jsonObject['predicate'] = 'required';
      } else {
        jsonObject['predicate'] = 'preferred';
      }
    }
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class HolderSubjectConstraint implements JsonObject {
  /// Identifies the attributes whose Subject is of concern to the Verifier
  late List<String> fieldId;

  /// Either `required` or `preferred`.
  ///
  /// - `required`: This indicates that the processing entity MUST include proof that the Subject of each attribute identified by a value in the field_id array is the same as the entity submitting the response.
  /// - `preferred`: This indicates that it is RECOMMENDED that the processing entity include proof that the Subject of each attribute identified by a value in the field_id array is the same as the entity submitting the response.
  late Limiting directive;

  HolderSubjectConstraint({required this.fieldId, required this.directive});

  HolderSubjectConstraint.fromJson(dynamic isHolderObject) {
    Map<String, dynamic> ih = credentialToMap(isHolderObject);
    if (ih.containsKey('field_id')) {
      fieldId = ih['field_id'].cast<String>();
    } else {
      throw FormatException(
          'field_id property is required for is_holder Object');
    }

    if (ih.containsKey('directive')) {
      String value = ih['directive'];
      if (value == 'preferred') {
        directive = Limiting.preferred;
      } else if (value == 'required') {
        directive = Limiting.required;
      } else {
        throw Exception('Unknown value for directive property');
      }
    } else {
      throw FormatException(
          'directive property is required for is_holder object');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['field_id'] = fieldId;
    if (directive == Limiting.required) {
      jsonObject['directive'] = 'required';
    } else {
      jsonObject['directive'] = 'preferred';
    }
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class StatusObject implements JsonObject {
  StatusDirective? active;
  StatusDirective? suspended;
  StatusDirective? revoked;

  StatusObject({this.active, this.suspended, this.revoked}) {
    if (revoked == null && suspended == null && active == null) {
      throw FormatException(
          'One property out of active, revoked and suspended must be given');
    }
  }

  StatusObject.fromJson(dynamic statusInput) {
    Map<String, dynamic> stat = credentialToMap(statusInput);
    if (stat.containsKey('active')) {
      active = _determineDirective(stat['active']['directive']);
    }
    if (stat.containsKey('suspended')) {
      suspended = _determineDirective(stat['suspended']['directive']);
    }
    if (stat.containsKey('revoked')) {
      revoked = _determineDirective(stat['revoked']['directive']);
    }

    if (revoked == null && suspended == null && active == null) {
      throw FormatException(
          'One property out of active, revoked and suspended must be given');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (active != null) {
      jsonObject['active'] = {'directive': _determineDirectiveString(active!)};
    }
    if (suspended != null) {
      jsonObject['suspended'] = {
        'directive': _determineDirectiveString(suspended!)
      };
    }
    if (revoked != null) {
      jsonObject['revoked'] = {
        'directive': _determineDirectiveString(revoked!)
      };
    }
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }

  StatusDirective _determineDirective(String directive) {
    if (directive == 'required') {
      return StatusDirective.required;
    } else if (directive == 'allowed') {
      return StatusDirective.allowed;
    } else if (directive == 'disallowed') {
      return StatusDirective.disallowed;
    } else {
      throw Exception('Unknown Status-Directive value');
    }
  }

  String _determineDirectiveString(StatusDirective directive) {
    if (directive == StatusDirective.disallowed) {
      return 'disallowed';
    } else if (directive == StatusDirective.allowed) {
      return 'allowed';
    } else {
      return 'required';
    }
  }
}

class SubmissionRequirement implements JsonObject {
  late SubmissionRequirementRule rule;
  String? from;
  List<SubmissionRequirement>? fromNested;
  String? name;
  String? purpose;
  int? min, max, count;

  SubmissionRequirement(
      {required this.rule,
      this.from,
      this.fromNested,
      this.name,
      this.purpose,
      this.max,
      this.count,
      this.min}) {
    if (from == null && fromNested == null) {
      throw FormatException('Need either from or fromNested');
    }
    if (from != null && fromNested != null) {
      throw FormatException('Do nut use  from and fromNested together');
    }
  }

  SubmissionRequirement.fromJson(dynamic requirementJson) {
    var requirement = credentialToMap(requirementJson);
    if (requirement.containsKey('rule')) {
      var tmpRule = requirement['rule'];
      if (tmpRule == 'all') {
        rule = SubmissionRequirementRule.all;
      } else if (tmpRule == 'pick') {
        rule = SubmissionRequirementRule.pick;
        if (requirement.containsKey('min')) {
          var minTmp = requirement['min'];
          min = minTmp is int ? minTmp : int.parse(minTmp);
          if (min! < 0) {
            throw Exception('min value must be greater than or equal to zero');
          }
        }
        if (requirement.containsKey('max')) {
          var maxTmp = requirement['max'];
          max = maxTmp is int ? maxTmp : int.parse(maxTmp);
          if (max! <= 0) throw Exception('max value must be greater than zero');
          if (min != null && max! <= min!) {
            throw Exception('max must be greater than min');
          }
        }
        if (requirement.containsKey('count')) {
          var countTemp = requirement['count'];
          count = countTemp is int ? countTemp : int.parse(countTemp);
          if (count! <= 0) throw Exception('count must greater than zero');
        }
      } else {
        throw Exception('Unknown value for rule');
      }
    } else {
      throw FormatException('Rule property is required');
    }

    if (requirement.containsKey('from')) from = requirement['from'];
    if (requirement.containsKey('from_nested')) {
      List tmp = requirement['from_nested'];
      if (tmp.isNotEmpty) {
        fromNested = [];
        for (var s in tmp) {
          fromNested!.add(SubmissionRequirement.fromJson(s));
        }
      }
    }

    if (from == null && fromNested == null) {
      throw FormatException('Need either from or fromNested');
    }
    if (from != null && fromNested != null) {
      throw FormatException('Do nut use  from and fromNested together');
    }

    if (requirement.containsKey('name')) name = requirement['name'];
    if (requirement.containsKey('purpose')) purpose = requirement['purpose'];
  }
  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (rule == SubmissionRequirementRule.pick) {
      jsonObject['rule'] = 'pick';
    } else {
      jsonObject['rule'] = 'all';
    }
    if (from != null) jsonObject['from'] = from;
    if (fromNested != null) {
      List tmp = [];
      for (var n in fromNested!) {
        tmp.add(n.toJson());
      }
      jsonObject['from_nested'] = tmp;
    }

    if (name != null) jsonObject['name'] = name;
    if (purpose != null) jsonObject['purpose'] = purpose;
    if (min != null) jsonObject['min'] = min;
    if (count != null) jsonObject['count'] = count;
    if (max != null) jsonObject['max'] = max;
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class FormatProperty implements JsonObject {
  JwtFormat? jwt;
  JwtFormat? jwtVc;
  JwtFormat? jwtVp;
  LinkedDataProofFormat? ldp;
  LinkedDataProofFormat? ldpVc;
  LinkedDataProofFormat? ldpVp;

  FormatProperty(
      {this.jwt, this.jwtVc, this.jwtVp, this.ldp, this.ldpVc, this.ldpVp});

  FormatProperty.fromJson(dynamic formatJson) {
    var format = credentialToMap(formatJson);
    if (format.containsKey('jwt')) jwt = JwtFormat.fromJson(format['jwt']);
    if (format.containsKey('jwt_vc')) {
      jwtVc = JwtFormat.fromJson(format['jwt_vc']);
    }
    if (format.containsKey(['jwt_vp'])) {
      jwtVp = JwtFormat.fromJson(format['jwt_vp']);
    }
    if (format.containsKey(['ldp'])) {
      ldp = LinkedDataProofFormat.fromJson(format['ldp']);
    }
    if (format.containsKey(['ldp_vc'])) {
      ldpVc = LinkedDataProofFormat.fromJson(format['ldp_vc']);
    }
    if (format.containsKey('ldp_vp')) {
      ldpVp = LinkedDataProofFormat.fromJson(format['ldp_vp']);
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (jwt != null) jsonObject['jwt'] = jwt!.toJson();
    if (jwtVp != null) jsonObject['jwt_vp'] = jwtVp!.toJson();
    if (jwtVc != null) jsonObject['jwt_vc'] = jwtVc!.toJson();
    if (ldp != null) jsonObject['ldp'] = ldp!.toJson();
    if (ldpVp != null) jsonObject['ldp_vp'] = ldpVp!.toJson();
    if (ldpVc != null) jsonObject['ldp_vc'] = ldpVc!.toJson();
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class JwtFormat implements JsonObject {
  late List<String> algorithms;

  JwtFormat({required this.algorithms});

  JwtFormat.fromJson(dynamic jwtFormatJson) {
    var jwtAlg = credentialToMap(jwtFormatJson);
    if (jwtAlg.containsKey('alg')) {
      algorithms = jwtAlg['alg'].cast<String>();
    } else {
      throw FormatException('JwtFormat needs alg property');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    return {'alg': algorithms};
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class LinkedDataProofFormat implements JsonObject {
  late List<String> proofType;

  LinkedDataProofFormat({required this.proofType});
  LinkedDataProofFormat.fromJson(dynamic proofTypeJson) {
    var proofTypeTmp = credentialToMap(proofTypeJson);
    if (proofTypeTmp.containsKey('proof_type')) {
      proofType = proofTypeTmp['proof_type'].cast<String>();
    } else {
      throw FormatException('JwtFormat needs alg property');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    return {'proof_type': proofType};
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

enum Limiting { required, preferred }

enum SubmissionRequirementRule { all, pick }

enum StatusDirective { required, allowed, disallowed }

/// Object used when a credential-List is filtered with a presentationDefinition
class FilterResult implements JsonObject {
  late List<VerifiableCredential> credentials;
  late String presentationDefinitionId;
  SubmissionRequirement? submissionRequirement;
  late List<String> matchingDescriptorIds;
  List<InputDescriptorConstraints>? selfIssuable;
  bool fulfilled;

  FilterResult(
      {required this.credentials,
      required this.matchingDescriptorIds,
      this.submissionRequirement,
      required this.presentationDefinitionId,
      this.selfIssuable,
      this.fulfilled = true});

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};

    List creds = [];
    for (var c in credentials) {
      creds.add(c.toJson());
    }
    jsonObject['credentials'] = creds;
    if (submissionRequirement != null) {
      jsonObject['submissionRequirement'] = submissionRequirement!.toJson();
    }

    jsonObject['matchingDescriptorIds'] = matchingDescriptorIds;

    if (selfIssuable != null && selfIssuable!.isNotEmpty) {
      List self = [];
      for (var i in selfIssuable!) {
        self.add(i.toJson());
      }
      jsonObject['selfIssuable'] = self;
    }

    jsonObject['fulfilled'] = fulfilled;

    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

//************** Presentation Submission **************************************
class PresentationSubmission implements JsonObject {
  late String id;
  late String presentationDefinitionId;
  late List<InputDescriptorMappingObject> descriptorMap;
  Map<String, dynamic>? _originalDoc;

  PresentationSubmission(
      {String? id,
      required this.presentationDefinitionId,
      required this.descriptorMap})
      : id = id ?? Uuid().v4();

  PresentationSubmission.fromJson(dynamic jsonObject) {
    Map<String, dynamic> submission = credentialToMap(jsonObject);
    if (submission.containsKey('id')) {
      id = submission['id'];
    } else {
      throw FormatException('Id Property is needed in presentation submission');
    }

    if (submission.containsKey('definition_id')) {
      presentationDefinitionId = submission['definition_id'];
    } else {
      throw FormatException(
          'Definition id is needed in presentation submission');
    }

    if (submission.containsKey('descriptor_map')) {
      List tmp = submission['descriptor_map'];
      descriptorMap = [];
      if (tmp.isNotEmpty) {
        for (var d in tmp) {
          descriptorMap.add(InputDescriptorMappingObject.fromJson(d));
        }
      }
    } else {
      throw FormatException(
          'descriptor_map property is needed in presentation submission');
    }

    _originalDoc = submission;
  }

  @override
  Map<String, dynamic> toJson() {
    if (_originalDoc != null) return _originalDoc!;

    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    jsonObject['definition_id'] = presentationDefinitionId;
    List tmp = [];
    for (var d in descriptorMap) {
      tmp.add(d.toJson());
    }
    jsonObject['descriptor_map'] = tmp;
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class InputDescriptorMappingObject implements JsonObject {
  late String id;
  late String format;
  late JsonPath path;
  Map<String, dynamic>? _originalDoc;

  InputDescriptorMappingObject(
      {required this.id, required this.format, required this.path});

  InputDescriptorMappingObject.fromJson(dynamic jsonObject) {
    Map<String, dynamic> descriptor = credentialToMap(jsonObject);
    if (descriptor.containsKey('id')) {
      id = descriptor['id'];
    } else {
      throw Exception('Id property is needed in descriptor-Map Object');
    }

    if (descriptor.containsKey('format')) {
      format = descriptor['format'];
    } else {
      throw Exception('Format property is needed in descriptor-map object');
    }

    if (descriptor.containsKey('path')) {
      path = JsonPath(descriptor['path']);
    } else {
      throw Exception(' path property is needed in descriptor-map object');
    }
    _originalDoc = descriptor;
  }

  @override
  Map<String, dynamic> toJson() {
    if (_originalDoc != null) return _originalDoc!;

    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    jsonObject['format'] = format;
    jsonObject['path'] = path.toString();
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
