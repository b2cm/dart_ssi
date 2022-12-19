/// This can be returned on any operation which may or may not succeed
/// for any defined reason
class Result<S, E> {
  final S? success;
  final E? error;
  final bool isOk;

  bool get isError => !isOk;

  /// Do not use this constructor, instead ise [Result.Ok] or [Result.Error]
  const Result._(this.isOk, {this.success, this.error});

  // ignore: non_constant_identifier_names
  factory Result.Ok(S result) {
    return Result._(
        true,
        success: result,
        error: null
    );
  }

  // ignore: non_constant_identifier_names
  factory Result.Error(E error) {
    return Result._(
        false,
        success: null,
        error: error
    );
  }

  /// Depending on [isOk] this will return the value of type [S] or type [E]
  dynamic unrwap() {
    if(isOk) return success!;
    return error!;
  }
}