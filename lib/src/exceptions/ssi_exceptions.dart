/// Most general Exception generated from this module
class SsiException implements Exception {

  // main message
  final String message;

  // unique error code
  final int code;

  // if the root of the error is something else
  final Exception? baseException;

  SsiException(this.message, {required this.code, this.baseException});

  @override
  String toString() {
    if (baseException != null) {
      return "$message (Code: $code)\nDetails: ${baseException.toString()}";
    }

    return "$message (Code: $code)";
  }

}
