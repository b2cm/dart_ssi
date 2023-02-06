import 'package:dart_ssi/exceptions.dart';

/// raised on some JSON-related error
class JsonException extends SsiException {
  JsonException(String message, {required int code}) : super(message, code: code);
}

/// raised when a location pointing to something in a JSON is invalid
class JsonPathException extends JsonException {
  JsonPathException(String message, {required int code})
      : super(message, code: code);
}
