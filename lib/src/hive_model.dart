import 'package:hive/hive.dart';
part 'hive_model.g.dart';

@HiveType(typeId: 0)
class Credential {
  @HiveField(0)
  String hdPath;
  @HiveField(1)
  String jsonCredential;

  Credential(this.hdPath, this.jsonCredential);

  @override
  String toString() => '$jsonCredential uses Path $hdPath';
}