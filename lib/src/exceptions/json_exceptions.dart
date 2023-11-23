import 'package:dart_ssi/exceptions.dart';

/// raised on some JSON-related error
class JsonException extends SsiException {
  JsonException(super.message, {required super.code});
}

/// raised when a location pointing to something in a JSON is invalid
class JsonPathException extends JsonException {
  JsonPathException(super.message, {required super.code});
}
