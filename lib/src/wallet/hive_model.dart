import 'package:dart_ssi/didcomm.dart';
import 'package:hive/hive.dart';

part 'hive_model.g.dart';

/// A credential when it is stored.
@HiveType(typeId: 0)
class Credential {
  /// Path used to derive keypair for proofing that one own it.
  @HiveField(0)
  String hdPath;

  /// Signed version according to W3C-Data Model with all attribute values hashed.
  @HiveField(1)
  String w3cCredential;

  /// Json-Structure containing hash, salt and value per attribute.
  @HiveField(2)
  String plaintextCredential;

  Credential(this.hdPath, this.w3cCredential, this.plaintextCredential);

  @override
  String toString() =>
      '$w3cCredential uses Path $hdPath an has this data: $plaintextCredential';
}

@HiveType(typeId: 1)

/// A connection with an other party (issuer, verifier,...).
class Connection {
  /// HD-Path for own key.
  @HiveField(0)
  String hdPath;

  /// Did of the other party.
  @HiveField(1)
  String otherDid;

  /// A nma efor this connection.
  @HiveField(2)
  String name;

  Connection(this.hdPath, this.otherDid, this.name);

  @override
  String toString() =>
      'Connection with $otherDid uses Path $hdPath und (user)name $name.';
}

@HiveType(typeId: 2)
class ExchangeHistoryEntry {
  @HiveField(0)
  DateTime timestamp;

  /// Description of the action done with the credential (Present, issue ...)
  @HiveField(1)
  String action;

  /// Did/name/url of party the credential was presented to
  @HiveField(2)
  String otherParty;

  /// Credential attributes that were shown
  @HiveField(3)
  List<String> shownAttributes;

  ExchangeHistoryEntry(
      this.timestamp, this.action, this.otherParty, this.shownAttributes);

  @override
  String toString() {
    return 'ExchangeHistoryEntry{timestamp: $timestamp, action: $action, otherParty: $otherParty, shownAttributes: $shownAttributes}';
  }
}

@HiveType(typeId: 3)
class DidcommConversation {
  /// Did/name/url of party the credential was presented to
  @HiveField(0)
  String lastMessage;

  @HiveField(1)
  String protocol;

  @HiveField(2)
  String myDid;

  DidcommConversation(this.lastMessage, this.protocol, this.myDid);

  @override
  String toString() {
    return 'DidcommConversation{lastMessage: $lastMessage, protocol: $protocol, myDid: $myDid}';
  }
}
