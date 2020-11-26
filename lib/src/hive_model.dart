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
