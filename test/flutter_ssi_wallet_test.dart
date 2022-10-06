import 'package:bip39/bip39.dart';
import 'package:dart_ssi/wallet.dart';
import 'package:test/test.dart';

void main() {
  test('init wallet with new seed', () async {
    var wallet = WalletStore('testNew');
    await wallet.openBoxes('password');
    var mne = await wallet.initialize();
    expect(validateMnemonic(mne!), true);
    await wallet.closeBoxes();
  });

  test('should increment index', () async {
    var wallet = WalletStore('testNew');
    await wallet.openBoxes('password');
    var indexBefore = wallet.getLastCredentialIndex()!;
    var did = await wallet.getNextCredentialDID();
    print(did);
    var indexAfter = wallet.getLastCredentialIndex();

    expect(indexAfter, indexBefore + 1);
  });
}
