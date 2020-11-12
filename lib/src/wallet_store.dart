library flutter_ssi_wallet;

import 'package:bip32/bip32.dart';
import 'package:bip39/bip39.dart';
import 'package:crypto/crypto.dart';
import 'package:hex/hex.dart';
import 'package:hive/hive.dart';
import 'package:pbkdf2_dart/pbkdf2_dart.dart';
import 'package:web3dart/credentials.dart';

import 'hive_model.dart';

class WalletStore {
  Box _keyBox;
  Box<Credential> _credentialBox;
  final String standardPath = 'm/456/0/';

  WalletStore(String path) {
    Hive.init(path);
    try {
      Hive.registerAdapter(CredentialAdapter());
    } catch (HiveError) {}
  }

  Future<void> openBoxes(String password) async {
    //password to AES-Key
    var generator = new PBKDF2(hash: sha256);
    var aesKey = generator.generateKey(password, "salt", 1000, 32);
    //only values are encrypted, keys are stored in plaintext
    this._keyBox = await Hive.openBox('keyBox', encryptionKey: aesKey);
    this._credentialBox =
        await Hive.openBox<Credential>('credentialBox', encryptionKey: aesKey);
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

  Future<String> initializeIssuer() async {
    var master = BIP32.fromSeed(_keyBox.get('seed'));
    var key = master.derivePath('m/456/1/0');
    var issuerDid = await _bip32KeyToDid(key);
    _keyBox.put('issuerDid', issuerDid);
    _credentialBox.put(issuerDid, new Credential('m/456/1/0', '', ''));
    return issuerDid;
  }

  String getStandardIssuerDid() {
    return _keyBox.get('issuerDid');
  }

  String getStandardIssuerPrivateKey() {
    return getPrivateKeyToDid(getStandardIssuerDid());
  }

  Map<dynamic, Credential> getAllCredentials() {
    var credMap = _credentialBox.toMap();
    return credMap;
  }

  Credential getCredential(String did) {
    return this._credentialBox.get(did);
  }

  Future<void> storeCredential(
      String w3cCred, String plaintextCred, String hdPath) async {
    var did = await getDid(hdPath);
    var tmp = new Credential(hdPath, w3cCred, plaintextCred);
    await this._credentialBox.put(did, tmp);
  }

  int getLastIndex() {
    return _keyBox.get('lastIndex');
  }

  Future<String> getNextDID() async {
    //generate new keypair
    var master = BIP32.fromSeed(_keyBox.get('seed'));
    var lastIndex = _keyBox.get('lastIndex');
    var path = '$standardPath${lastIndex.toString()}';
    var key = master.derivePath(path);

    //increment derivation index
    lastIndex++;
    await _keyBox.put('lastIndex', lastIndex);

    var did = await _bip32KeyToDid(key);

    //store temporarily
    _credentialBox.put(did, new Credential(path, '', ''));

    return did;
  }

  String getTmpStoredPath(String did) {
    return _keyBox.get(did);
  }

  Future<String> getDid(String hdPath) async {
    var master = BIP32.fromSeed(_keyBox.get('seed'));
    var key = master.derivePath(hdPath);
    return await _bip32KeyToDid(key);
  }

  String getPrivateKey(String hdPath) {
    var master = BIP32.fromSeed(_keyBox.get('seed'));
    var key = master.derivePath(hdPath);
    return HEX.encode(key.privateKey);
  }

  String getPublicKey(String hdPath) {
    var master = BIP32.fromSeed(_keyBox.get('seed'));
    var key = master.derivePath(hdPath);
    return HEX.encode(key.publicKey);
  }

  String getPrivateKeyToDid(String did) {
    var cred = getCredential(did);
    var master = BIP32.fromSeed(_keyBox.get('seed'));
    var key = master.derivePath(cred.hdPath);
    return HEX.encode(key.privateKey);
  }

  Future<String> _bip32KeyToDid(BIP32 key) async {
    var private = EthPrivateKey.fromHex(HEX.encode(key.privateKey));
    var addr = await private.extractAddress();
    return 'did:ethr:${addr.hexEip55.substring(2)}';
  }
}
