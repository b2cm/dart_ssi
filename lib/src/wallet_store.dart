library flutter_ssi_wallet;

import 'package:bip32/bip32.dart';
import 'package:bip39/bip39.dart';
import 'package:hex/hex.dart';
import 'package:hive/hive.dart';
import 'package:web3dart/credentials.dart';

import 'hive_model.dart';

class WalletStore {
  Box _keyBox;
  Box<Credential> _credentialBox;
  final String standardPath = 'm/456/0/';

  WalletStore(String path) {
    Hive.init(path);
  }

  Future<void> openBoxes(String password) async {
    //TODO password to AES-Key
    this._keyBox = await Hive.openBox('keyBox');
    this._credentialBox = await Hive.openBox<Credential>('credentialBox');
  }

  Future<void> closeBoxes() async {
    await _keyBox.close();
    await _credentialBox.close();
  }

  String initialize([String mnemonic]) {
    var mne = mnemonic;
    if (mnemonic == null) {
      mne = generateMnemonic();
    }
    var seed = mnemonicToSeed(mne);

    this._keyBox.put('seed', seed);
    this._keyBox.put('lastIndex', 0);

    return mne;
  }

  List<String> getAllCredentials() {
    var credMap = _credentialBox.toMap();
    var credList = new List();
    for (var item in credMap.values) {
      credList.add(item.jsonCredential);
    }
    return credList;
  }

  String getCredential(String did) {
    return this._credentialBox.get(did).jsonCredential;
  }

  void storeCredential(String cred, String hdPath) {
    Credential tmp = new Credential(hdPath, cred);
    this._credentialBox.put('did:ethr', tmp);
  }

  int getLastIndex() {
    return _keyBox.get('lastIndex');
  }

  Future<String> getNextDID() async {
    //generate new keypair
    BIP32 master = BIP32.fromSeed(_keyBox.get('seed'));
    var lastIndex = _keyBox.get('lastIndex');
    var path = '$standardPath${lastIndex.toString()}';
    var key = master.derivePath(path);

    //increment derivation index
    lastIndex++;
    _keyBox.put('lastIndex', lastIndex);

    var did = await _bip32KeyToDid(key);

    // store temporarily
    _keyBox.put(did, path);

    return did;
  }

  String getTmpStoredPath(String did) {
    return _keyBox.get(did);
  }

  Future<String> getDid(String hdPath) async {
    BIP32 master = BIP32.fromSeed(_keyBox.get('seed'));
    var key = master.derivePath(hdPath);
    return await _bip32KeyToDid(key);
  }

  String getPrivateKey(String hdPath) {
    BIP32 master = BIP32.fromSeed(_keyBox.get('seed'));
    var key = master.derivePath(hdPath);
    return HEX.encode(key.privateKey);
  }

  String getPublicKey(String hdPath) {
    BIP32 master = BIP32.fromSeed(_keyBox.get('seed'));
    var key = master.derivePath(hdPath);
    return HEX.encode(key.publicKey);
  }

  Future<String> _bip32KeyToDid(BIP32 key) async {
    var private = EthPrivateKey.fromHex(HEX.encode(key.privateKey));
    var addr = await private.extractAddress();
    return 'did:ethr:${addr.hexEip55.substring(2)}';
  }
}
