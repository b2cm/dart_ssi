library flutter_ssi_wallet;

import 'package:bip32/bip32.dart';
import 'package:bip39/bip39.dart';
import 'package:crypto/crypto.dart';
import 'package:hex/hex.dart';
import 'package:hive/hive.dart';
import 'package:pbkdf2_dart/pbkdf2_dart.dart';
import 'package:web3dart/credentials.dart';

import 'hive_model.dart';

/// A wallet storing credentials and keys permanently using Hive.
///
/// Keys are stored and generated according to BIP32 standard.
/// Per default the path m/456/0/index is used for keys and dids to prove and identify the credentials someone hold.
/// If a wallet is also used to issue credentials the keypair found at path m/456/1/0  is the default one.
class WalletStore {
  Box _keyBox;
  Box<Credential> _credentialBox;

  ///The Path used to derive keys
  final String standardPath = 'm/456/0/';

  /// Constructs a wallet at file-system path [path]
  WalletStore(String path) {
    Hive.init(path);
    try {
      Hive.registerAdapter(CredentialAdapter());
    } catch (HiveError) {}
  }

  /// Opens storage containers encrypted with [password]
  Future<void> openBoxes(String password) async {
    //password to AES-Key
    var generator = new PBKDF2(hash: sha256);
    var aesKey = generator.generateKey(password, "salt", 1000, 32);
    //only values are encrypted, keys are stored in plaintext
    this._keyBox = await Hive.openBox('keyBox', encryptionKey: aesKey);
    this._credentialBox =
        await Hive.openBox<Credential>('credentialBox', encryptionKey: aesKey);
  }

  /// Closes Storage Containers
  Future<void> closeBoxes() async {
    await _keyBox.close();
    await _credentialBox.close();
  }

  /// Initializes new hierarchical deterministic wallet or restores one from given mnemonic.
  ///
  /// Returns the used mnemonic.
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

  /// Generates and returns DID for the issuer.
  Future<String> initializeIssuer() async {
    var master = BIP32.fromSeed(_keyBox.get('seed'));
    var key = master.derivePath('m/456/1/0');
    var issuerDid = await _bip32KeyToDid(key);
    _keyBox.put('issuerDid', issuerDid);
    _credentialBox.put(issuerDid, new Credential('m/456/1/0', '', ''));
    return issuerDid;
  }

  /// Returns the DID for issuing credentials.
  String getStandardIssuerDid() {
    return _keyBox.get('issuerDid');
  }

  /// Returns the private key for issuing credentials.
  String getStandardIssuerPrivateKey() {
    return getPrivateKeyToDid(getStandardIssuerDid());
  }

  /// Lists all Credentials.
  Map<dynamic, Credential> getAllCredentials() {
    var credMap = _credentialBox.toMap();
    return credMap;
  }

  /// Returns the credential associated with [did].
  Credential getCredential(String did) {
    return this._credentialBox.get(did);
  }

  /// Stores a credential permanently.
  ///
  /// What should be stored consists of three parts
  /// - a signed credential [w3cCred] containing hashes of all attribute-values
  /// - a json structure [plaintextCred] containing hashes, salts and values per credential attribute
  /// - the [hdPath] to derive the key for the did the credential is issued for
  Future<void> storeCredential(
      String w3cCred, String plaintextCred, String hdPath) async {
    var did = await getDid(hdPath);
    var tmp = new Credential(hdPath, w3cCred, plaintextCred);
    await this._credentialBox.put(did, tmp);
  }

  /// Returns the last value of the next HD-path.
  int getLastIndex() {
    return _keyBox.get('lastIndex');
  }

  /// Returns a new DID.
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

  /// Returns the DID associated with [hdPath].
  Future<String> getDid(String hdPath) async {
    var master = BIP32.fromSeed(_keyBox.get('seed'));
    var key = master.derivePath(hdPath);
    return await _bip32KeyToDid(key);
  }

  /// Returns the private key as hex-String associated with [hdPath].
  String getPrivateKey(String hdPath) {
    var master = BIP32.fromSeed(_keyBox.get('seed'));
    var key = master.derivePath(hdPath);
    return HEX.encode(key.privateKey);
  }

  /// Returns the public key as hex-String associated with [hdPath].
  String getPublicKey(String hdPath) {
    var master = BIP32.fromSeed(_keyBox.get('seed'));
    var key = master.derivePath(hdPath);
    return HEX.encode(key.publicKey);
  }

  /// Returns the private key as hex-String associated with [did].
  String getPrivateKeyToDid(String did) {
    var cred = getCredential(did);
    var master = BIP32.fromSeed(_keyBox.get('seed'));
    var key = master.derivePath(cred.hdPath);
    return HEX.encode(key.privateKey);
  }

  Future<String> _bip32KeyToDid(BIP32 key) async {
    var private = EthPrivateKey.fromHex(HEX.encode(key.privateKey));
    var addr = await private.extractAddress();
    return 'did:ethr:${addr.hexEip55}';
  }
}
