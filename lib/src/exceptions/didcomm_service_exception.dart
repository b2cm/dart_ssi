import 'package:dart_ssi/src/exceptions/ssi_exceptions.dart';

class DidcommServiceException extends SsiException {
  DidcommServiceException(super.message,
      {required super.code, Exception? baseException});
}
