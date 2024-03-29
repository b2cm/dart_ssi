import 'dart:convert';

import 'package:uuid/uuid.dart';

import '../../util/types.dart';
import '../../util/utils.dart';
import '../didcomm_jwm.dart';
import '../types.dart';

class QueryMessage extends DidcommPlaintextMessage {
  late List<Query> queries;

  QueryMessage(
      {String? id,
      super.parentThreadId,
      super.ack,
      required this.queries,
      super.replyUrl,
      super.replyTo,
      super.threadId,
      super.from,
      List<String>? super.to,
      super.createdTime,
      super.expiresTime,
      super.pleaseAck,
      super.fromPrior,
      super.additionalHeaders,
      super.webRedirect,
      super.returnRoute,
      super.typ})
      : super(
            id: id ?? Uuid().v4(),
            type: DidcommMessages.discoverFeatureQuery,
            body: {}) {
    List<Map<String, dynamic>> q = [];
    for (var query in queries) {
      q.add(query.toJson());
    }
    body['queries'] = q;
  }

  QueryMessage.fromJson(super.jsonObject) : super.fromJson() {
    if (type != DidcommMessages.discoverFeatureQuery) {
      throw Exception('Wrong message type');
    }
    if (body.containsKey('queries')) {
      var q = body['queries'] as List;
      queries = [];
      for (var query in q) {
        queries.add(Query.fromJson(query));
      }
    } else {
      throw FormatException('queries property is needed in Query Message');
    }
  }
}

class DiscloseMessage extends DidcommPlaintextMessage {
  late List<Disclosure> disclosures;

  DiscloseMessage(
      {String? id,
      super.parentThreadId,
      super.ack,
      required this.disclosures,
      super.replyUrl,
      super.replyTo,
      super.threadId,
      super.from,
      List<String>? super.to,
      super.createdTime,
      super.expiresTime,
      super.pleaseAck,
      super.fromPrior,
      super.additionalHeaders,
      super.webRedirect,
      super.returnRoute,
      super.typ})
      : super(
            id: id ?? Uuid().v4(),
            type: DidcommMessages.discoverFeatureDisclose,
            body: {}) {
    List<Map<String, dynamic>> d = [];
    for (var dis in disclosures) {
      d.add(dis.toJson());
    }
    body['disclosures'] = d;
  }

  DiscloseMessage.fromJson(super.jsonObject) : super.fromJson() {
    if (type != DidcommMessages.discoverFeatureDisclose) {
      throw Exception('Wrong message type');
    }
    if (body.containsKey('disclosures')) {
      var d = body['disclosures'] as List;
      disclosures = [];
      for (var dis in d) {
        disclosures.add(Disclosure.fromJson(dis));
      }
    } else {
      throw FormatException(
          'disclosures property is needed in Disclosure Message');
    }
  }
}

class Query implements JsonObject {
  late FeatureType featureType;
  late String match;

  Query({required this.featureType, required this.match});

  Query.fromJson(dynamic query) {
    Map<String, dynamic> decoded = credentialToMap(query);
    if (decoded.containsKey('feature-type')) {
      var fType = decoded['feature-type'];
      if (fType == FeatureType.header.value) {
        featureType = FeatureType.header;
      } else if (fType == FeatureType.goalCode.value) {
        featureType = FeatureType.goalCode;
      } else if (fType == FeatureType.protocol.value) {
        featureType = FeatureType.protocol;
      } else if (fType == FeatureType.attachmentFormat.value) {
        featureType = FeatureType.attachmentFormat;
      } else {
        throw Exception('unknown Feature-type');
      }
    } else {
      throw Exception('Property Feature-Type is needed');
    }

    if (decoded.containsKey('match')) {
      match = decoded['match'];
    } else {
      throw Exception('Property match is needed');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    return {'feature-type': featureType.value, 'match': match};
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class Disclosure implements JsonObject {
  late FeatureType featureType;
  late String id;
  List<String>? roles;

  Disclosure({required this.featureType, required this.id, this.roles});

  Disclosure.fromJson(dynamic jsonObject) {
    var decoded = credentialToMap(jsonObject);

    if (decoded.containsKey('feature-type')) {
      var fType = decoded['feature-type'];
      if (fType == FeatureType.header.value) {
        featureType = FeatureType.header;
      } else if (fType == FeatureType.goalCode.value) {
        featureType = FeatureType.goalCode;
      } else if (fType == FeatureType.protocol.value) {
        featureType = FeatureType.protocol;
      } else if (fType == FeatureType.attachmentFormat.value) {
        featureType = FeatureType.attachmentFormat;
      } else {
        throw Exception('unknown Feature-type');
      }
    } else {
      throw Exception('Property Feature-Type is needed');
    }

    if (decoded.containsKey('id')) {
      id = decoded['id'];
    } else {
      throw Exception('property id is needed in Disclosure-object');
    }

    if (decoded.containsKey('roles')) {
      roles = decoded['roles'].cast<String>();
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> asMap = {'feature-type': featureType.value, 'id': id};
    if (roles != null && roles!.isNotEmpty) {
      asMap['roles'] = roles;
    }
    return asMap;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

enum FeatureType {
  protocol,
  goalCode,
  header,
  attachmentFormat;

  static const Map<FeatureType, String> stringValues = {
    FeatureType.goalCode: 'goal-code',
    FeatureType.header: 'header',
    FeatureType.protocol: 'protocol',
    FeatureType.attachmentFormat: 'attachment-format'
  };
  String get value => stringValues[this]!;
}
