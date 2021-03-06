import 'package:bip39/bip39.dart';
import 'package:flutter_ssi_wallet/flutter_ssi_wallet.dart';
import 'package:test/test.dart';

void main() {
  test('init wallet with new seed', () async {
    var wallet = new WalletStore('testNew');
    await wallet.openBoxes('password');
    var mne = wallet.initialize()!;
    expect(validateMnemonic(mne), true);
    await wallet.closeBoxes();
  });

  test('should increment index', () async {
    var wallet = new WalletStore('testNew');
    await wallet.openBoxes('password');
    var indexBefore = wallet.getLastIndex()!;
    var did = await wallet.getNextCredentialDID();
    print(did);
    var indexAfter = wallet.getLastIndex();

    expect(indexAfter, indexBefore + 1);
  });
}
