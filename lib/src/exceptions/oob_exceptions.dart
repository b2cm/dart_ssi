
import 'package:dart_ssi/exceptions.dart';

/// Raised when something related to Oob goes south
class OobException extends SsiException {
  OobException(super.message, {required super.code});
}

/// Raised when something is wrong with the template
class OobTemplateException extends OobException {
  OobTemplateException(super.message, {required super.code});
}

/// a missing field in a oob template
class OobTemplateMissingValueException extends OobTemplateException {
  OobTemplateMissingValueException(super.message, {required super.code});
}

/// Some template value is there but is not valid
class OobTemplateWrongValueException extends OobTemplateException {
  OobTemplateWrongValueException(super.message, {required super.code});
}
