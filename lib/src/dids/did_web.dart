import 'package:http/http.dart';

import 'did_document.dart';

Future<DidDocument> resolveDidWeb(String didToResolve) async {
  var did = didToResolve.replaceFirst('did:web:', '');
  did = did.replaceAll(':', '/');
  did = did.replaceAll('%3A', ':');
  did = did.replaceAll('%2B', '/');
  did = 'https://$did';
  var asUri = Uri.parse(did);
  if (asUri.hasEmptyPath) {
    did = '$did/.well-known';
  }
  did = '$did/did.json';

  var res = await get(Uri.parse(did), headers: {'Accept': 'application/json'});
  if (res.statusCode == 200) {
    return DidDocument.fromJson(res.body);
  } else {
    throw Exception('Cant\'t fetch document for $didToResolve');
  }
}
