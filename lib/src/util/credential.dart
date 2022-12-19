import 'dart:convert';

import 'package:dart_ssi/credentials.dart';
import 'package:dart_ssi/didcomm.dart';
import 'package:dart_ssi/wallet.dart';

/// will search matching credentials in [wallet] given a presentation request
/// [message] and return a list of [FilterResult]s
Future<List<FilterResult>> searchForMatchingCredentials({
  required RequestPresentation message,
  required WalletStore wallet,
  }
) async {
  List<FilterResult> finalShow = [];
  var allCreds = wallet.getAllCredentials();
  List<Map<String, dynamic>> creds = [];

  allCreds.forEach((key, value) {
    if (value.w3cCredential != '') creds.add(jsonDecode(value.w3cCredential));
  });

  var definition = message.presentationDefinition.first.presentationDefinition;
  var filtered = searchCredentialsForPresentationDefinition(creds, definition);

  if (filtered.isNotEmpty) {
    //filter List of credentials -> check for duplicates by type
    for (var result in filtered) {
      List<VerifiableCredential> filteredCreds = [];
      for (var cred in result.credentials) {
        if (filteredCreds.isEmpty) {
          filteredCreds.add(cred);
        } else {
          bool typeFound = false;
          for (var cred2 in filteredCreds) {
            if (cred.isOfSameType(cred2)) {
              typeFound = true;
              break;
            }
          }
          if (!typeFound) filteredCreds.add(cred);
        }
      }

      finalShow.add(FilterResult(
          credentials: filteredCreds,
          presentationDefinitionId: definition.id,
          matchingDescriptorIds: result.matchingDescriptorIds,
          submissionRequirement: result.submissionRequirement));
    }
  }

  return finalShow;
}
