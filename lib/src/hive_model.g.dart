// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'hive_model.dart';

// **************************************************************************
// TypeAdapterGenerator
// **************************************************************************

class CredentialAdapter extends TypeAdapter<Credential> {
  @override
  final int typeId = 0;

  @override
  Credential read(BinaryReader reader) {
    final numOfFields = reader.readByte();
    final fields = <int, dynamic>{
      for (int i = 0; i < numOfFields; i++) reader.readByte(): reader.read(),
    };
    return Credential(
      fields[0] as String,
      fields[1] as String,
    );
  }

  @override
  void write(BinaryWriter writer, Credential obj) {
    writer
      ..writeByte(2)
      ..writeByte(0)
      ..write(obj.hdPath)
      ..writeByte(1)
      ..write(obj.jsonCredential);
  }

  @override
  int get hashCode => typeId.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is CredentialAdapter &&
          runtimeType == other.runtimeType &&
          typeId == other.typeId;
}
