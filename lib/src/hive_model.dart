import 'package:hive/hive.dart';

part 'hive_model.g.dart';

@HiveType(typeId: 0)
class Credential {
  @HiveField(0)
  String hdPath;
  @HiveField(1)
  String w3cCredential;
  @HiveField(2)
  String plaintextCredential;

  Credential(this.hdPath, this.w3cCredential, this.plaintextCredential);

  @override
  String toString() =>
      '$w3cCredential uses Path $hdPath an has this data: $plaintextCredential';
}
