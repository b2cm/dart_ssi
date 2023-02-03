import 'package:dart_ssi/exceptions.dart';

/// this type is to define a path to a json
///
/// each members has to be a String ot a Int
/// @todo fixme: dynamic should be String|Int
typedef SimpleJsonPath = List<dynamic>;
typedef Json = Map<String, dynamic>;

/// Just add convenience methods to the type
extension on SimpleJsonPath {
  prettyPrint() {
    return "ROOT${map((val) => '[${val is String ? '"$val"' : val}]').join('')}";
  }
}


/// tries to follow a given [path] in a [json] mapping
///
/// e.g.
/// ```dart
/// var json = {'test': [2, {'hallo': 'welt'}]};
/// var path = ['test', 1, 'hallo'];
/// var result = getByPath(json, path);
/// # result == 'welt';
///
/// if [path] is empty, the [json] is returned as is
/// will raise a [JsonPathNotFoundException] if the path is not found
/// ```
dynamic getByPath(Json json, SimpleJsonPath path) {
  if (path.isEmpty) {
    return json;
  }
  SimpleJsonPath currentPath = [];
  dynamic current = json;

  // iterate over each part segment
  for (var part in path) {
    currentPath.add(part);
    if (part.runtimeType == int) {
      if (current.runtimeType != List) {
        throw JsonPathException(
            'Element `${currentPath.prettyPrint()}` is not a list, '
                'but a `${current.runtimeType}`.', code: 234839405);
      }
      current = current[part];
    } else if (part.runtimeType == String) {

      // check if the thing is map-able
      // note that jsonDecode returns a _InternalLinkedHashMap
      // which for whatever reason is not a Map, so we cannot just check it
      if (current.containsKey(part)) {
        current = current[part];
      } else {
        throw JsonPathException(
            'Element `${currentPath.prettyPrint()}` was not found', code: 429348534);
      }
    } else { // invalid path segment
      throw JsonPathException('Path at ${currentPath.prettyPrint()} '
          'is not a valid path. '
          'Only String and Integer elements are allowed.', code: 4583904);
    }
  }

  return current;
}

/// will force an entry which may come es a string into a list if
/// it is not already.
/// @hint this is an inplace operation!
forceAsList(Json json, SimpleJsonPath path) {
  if (path.isEmpty) {
    throw JsonPathException('Path must not be empty', code: 2349888823);
  }
  var value = getByPath(json, path);
  var parent = getByPath(json, path.sublist(0, path.length - 1));
  var key = path.last;

  if (value.runtimeType != List) {
    parent[key] = [value];
  }

  return value;
}

/// will set a value at specific position in a json
///
/// @hint if [path] points to an *existing element*, it will be *overwritten!*
/// @hint this is an inplace operation!
setValueInJson(Json json, SimpleJsonPath path, dynamic value) {
  var parent = getByPath(json, path.sublist(0, path.length - 1));
  var key = path.last;

  parent[key] = value;
}

/// will create a list or add an element to an existing list
///
/// if [path] does exists but doesn't point to a list a
/// [JsonPathException] will be thrown
addElementToListOrInit(Json json, SimpleJsonPath path, dynamic value) {
  var parent = getByPath(json, path.sublist(0, path.length - 1));
  var key = path.last;

  if (parent[key] == null) {
    parent[key] = [value];
  } else {
    var value = parent[key];
    if (value.runtimeType != List) {
      throw JsonPathException('Expected element at ${path.prettyPrint()} to '
          'be a list, (or not being set at all) '
          'but a `${value.runtimeType}` was found,', code: 423423423);
    }
    parent[key].add(value);
  }
}
