
import 'package:dart_ssi/exceptions.dart';

/// Raised when something related to Oob goes south
class OobException extends SsiException {
  OobException(String message, {required int code}) : super(message, code: code);
}

/// Raised when something is wrong with the template
class OobTemplateException extends OobException {
  OobTemplateException(String message, {required int code})
      : super(message, code: code);
}

/// a missing field in a oob template
class OobTemplateMissingValueException extends OobTemplateException {
  OobTemplateMissingValueException(String message, {required int code})
      : super(message, code: code);
}

/// Some template value is there but is not valid
class OobTemplateWrongValueException extends OobTemplateException {
  OobTemplateWrongValueException(String message, {required int code})
      : super(message, code: code);
}
