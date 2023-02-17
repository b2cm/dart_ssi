import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/src/util/utils.dart';
import 'package:dart_ssi/src/wallet/wallet_store.dart';

class RevocationList2020Status extends CredentialStatus {
  late String revocationListIndex;
  late String revocationListCredential;

  RevocationList2020Status(
      {required String id,
      required this.revocationListCredential,
      required this.revocationListIndex,
      Map<String, dynamic>? originalData})
      : super(id, 'RevocationList2020Status', originalData);

  factory RevocationList2020Status.fromJson(dynamic jsonData) {
    var data = credentialToMap(jsonData);

    String id;
    if (data.containsKey('id')) {
      id = data['id'];
    } else {
      throw FormatException('id property is needed in Credential Status');
    }
    String type;
    if (data.containsKey('type')) {
      type = data['type'];
      if (type != 'RevocationList2020Status') {
        throw Exception('type must be RevocationList2020Status');
      }
    } else {
      throw FormatException('type property is needed in credentialStatus');
    }
    String revocationListIndex;
    if (data.containsKey('revocationListIndex')) {
      revocationListIndex = data['revocationListIndex'];
    } else {
      throw Exception('revocationListIndex needed');
    }

    String revocationListCredential;
    if (data.containsKey('revocationListCredential')) {
      revocationListCredential = data['revocationListCredential'];
    } else {
      throw Exception('revocationListCredential needed');
    }

    return RevocationList2020Status(
        id: id,
        revocationListCredential: revocationListCredential,
        revocationListIndex: revocationListIndex,
        originalData: data);
  }

  @override
  Map<String, dynamic> toJson() {
    var tmp = super.toJson();
    if (tmp.containsKey('revocationListCredential')) {
      return tmp;
    } else {
      tmp['revocationListIndex'] = revocationListIndex;
      tmp['revocationListCredential'] = revocationListCredential;
      return tmp;
    }
  }
}

class StatusList2021Entry extends CredentialStatus {
  late String statusListIndex;
  late String statusListCredential;
  late CredentialStatus2021Purpose statusPurpose;

  StatusList2021Entry(
      {required String id,
      required this.statusPurpose,
      required this.statusListCredential,
      required this.statusListIndex,
      Map<String, dynamic>? originalData})
      : super(id, 'StatusList2021Entry', originalData);

  factory StatusList2021Entry.fromJson(dynamic jsonData) {
    var data = credentialToMap(jsonData);

    String id;
    if (data.containsKey('id')) {
      id = data['id'];
    } else {
      throw FormatException('id property is needed in Credential Status');
    }

    String type;
    if (data.containsKey('type')) {
      type = data['type'];
      if (type != 'StatusList2021Entry') {
        throw Exception('type must be StatusList2021Entry');
      }
    } else {
      throw FormatException('type property is needed in credentialStatus');
    }

    String statusListIndex;
    if (data.containsKey('statusListIndex')) {
      statusListIndex = data['statusListIndex'];
    } else {
      throw Exception('statusListIndex needed');
    }

    String statusListCredential;
    if (data.containsKey('statusListCredential')) {
      statusListCredential = data['statusListCredential'];
    } else {
      throw Exception('statusListCredential needed');
    }

    CredentialStatus2021Purpose statusPurpose;
    var purpose = data['statusPurpose'];
    if (purpose == CredentialStatus2021Purpose.revocation.value) {
      statusPurpose = CredentialStatus2021Purpose.revocation;
    } else if (purpose == CredentialStatus2021Purpose.suspension.value) {
      statusPurpose = CredentialStatus2021Purpose.suspension;
    } else {
      throw Exception('Unknown StatusPurpose');
    }

    return StatusList2021Entry(
        id: id,
        statusListCredential: statusListCredential,
        statusListIndex: statusListIndex,
        statusPurpose: statusPurpose,
        originalData: data);
  }

  @override
  Map<String, dynamic> toJson() {
    var tmp = super.toJson();
    if (tmp.containsKey('statusListCredential')) {
      return tmp;
    } else {
      tmp['statusListIndex'] = statusListIndex;
      tmp['statusListCredential'] = statusListCredential;
      tmp['statusPurpose'] = statusPurpose.value;
      return tmp;
    }
  }
}

enum CredentialStatus2021Purpose {
  revocation,
  suspension;

  static const Map<CredentialStatus2021Purpose, String> stringValues = {
    CredentialStatus2021Purpose.revocation: 'revocation',
    CredentialStatus2021Purpose.suspension: 'suspension'
  };
  String get value => stringValues[this]!;
}

class StatusList2021Credential extends RevocationList2020Credential {
  late CredentialStatus2021Purpose statusPurpose;

  StatusList2021Credential(
      {String? subjectId,
      required BitString revocationList,
      required this.statusPurpose,
      required String id,
      required DateTime issuanceDate,
      dynamic issuer,
      required DateTime expirationDate})
      : super(
            subjectId: subjectId,
            revocationList: revocationList,
            id: id,
            issuanceDate: issuanceDate,
            issuer: issuer,
            expirationDate: expirationDate) {
    type = ["VerifiableCredential", "StatusList2021Credential"];
    context = [credentialsV1Iri, statusList2021ContextIri];
    credentialSubject = {
      subjectId != null ? 'id' : subjectId: null,
      'type': 'StatusList2021',
      'statusPurpose': statusPurpose.value,
      'encodedList': revocationList.toEncodedString()
    };
  }

  StatusList2021Credential.fromJson(dynamic jsonData)
      : super.fromJson(jsonData) {
    var purpose = credentialSubject['statusPurpose'];
    if (purpose == CredentialStatus2021Purpose.revocation.value) {
      statusPurpose = CredentialStatus2021Purpose.revocation;
    } else if (purpose == CredentialStatus2021Purpose.suspension.value) {
      statusPurpose = CredentialStatus2021Purpose.suspension;
    } else {
      throw Exception('Unknown StatusPurpose');
    }
  }
}

class RevocationList2020Credential extends VerifiableCredential {
  String? subjectId;
  late BitString revocationList;

  RevocationList2020Credential(
      {this.subjectId,
      required this.revocationList,
      required String id,
      required DateTime issuanceDate,
      dynamic issuer,
      required DateTime expirationDate})
      : super(
            id: id,
            context: [credentialsV1Iri, revocationList202ContextIri],
            type: ["VerifiableCredential", "RevocationList2020Credential"],
            credentialSubject: {},
            issuanceDate: issuanceDate,
            issuer: issuer,
            expirationDate: expirationDate) {
    credentialSubject = {
      subjectId != null ? 'id' : subjectId: null,
      'type': 'RevocationList2020',
      'encodedList': revocationList.toEncodedString()
    };
  }

  RevocationList2020Credential.fromJson(dynamic jsonData)
      : super.fromJson(jsonData) {
    subjectId = credentialSubject['id'];

    var type = credentialSubject['type'];
    if (type == null) {
      throw Exception('type property in credentialSubject is expected');
    }

    var encodedString = credentialSubject['encodedList'];
    if (encodedString == null) {
      throw Exception('encodedList is expected in credentialSubject');
    }
    revocationList = BitString.fromEncoded(encodedString);
  }

  Future<RevocationList2020Credential> revoke(
      int indexToRevoke, WalletStore wallet) async {
    revocationList.flipBit(indexToRevoke);
    return RevocationList2020Credential.fromJson(
        await signCredential(wallet, toJson()));
  }

  Future<RevocationList2020Credential> batchRevoke(
      List<int> indexToRevoke, WalletStore wallet) async {
    for (var i in indexToRevoke) {
      revocationList.flipBit(i);
    }
    return RevocationList2020Credential.fromJson(
        await signCredential(wallet, toJson()));
  }

  bool isRevoked(int index) {
    return revocationList.getAt(index);
  }
}

class BitString {
  int _length;
  Uint8List _data;

  BitString(this._length, this._data);

  factory BitString.fromLength(int length) {
    var data = Uint8List((length / 8).ceil());

    return BitString(length, data);
  }

  factory BitString.fromEncoded(String encodedData) {
    var data = Uint8List.fromList(
        gzip.decode(base64Decode(addPaddingToBase64(encodedData))));
    var length = data.length * 8;

    return BitString(length, data);
  }

  void flipBit(int position) {
    if (position > _length) {
      throw Exception('requested position is out of range');
    }
    var posInData = position ~/ 8;
    var posInByte = position % 8;
    var mask = pow(2, posInByte).toInt();

    _data[posInData] ^= mask;
  }

  bool getAt(int position) {
    if (position > _length) {
      throw Exception('requested position is out of range');
    }
    var posInData = position ~/ 8;
    var posInByte = position % 8;

    var byte = _data[posInData];
    var asString = byte.toRadixString(2).padLeft(8, '0').split('');

    var bit = asString[posInByte];
    if (bit == '0') {
      return false;
    } else {
      return true;
    }
  }

  String toEncodedString() =>
      removePaddingFromBase64(base64UrlEncode(gzip.encode(_data)));

  List<int> toCompressed() => gzip.encode(_data);

  @override
  String toString() => _data.fold(
      '',
      (previousValue, element) =>
          '${element.toRadixString(2).padLeft(8, '0')} $previousValue');

  Uint8List get data => _data;
  int get length => _length;
}
