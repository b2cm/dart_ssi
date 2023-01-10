import 'package:dart_ssi/src/exceptions/ssi_exceptions.dart';

class DidcommServiceException extends SsiException {
  DidcommServiceException(String message,
      {required int code, Exception? baseException}) : super(message, code: code);
}
