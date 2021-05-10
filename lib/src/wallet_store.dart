library flutter_ssi_wallet;

import 'package:bip32/bip32.dart';
import 'package:bip39/bip39.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter_ssi_wallet/src/private_util.dart';
import 'package:hex/hex.dart';
import 'package:hive/hive.dart';
import 'package:web3dart/credentials.dart';
import 'package:web3dart/crypto.dart';

import 'hive_model.dart';

/// A wallet storing credentials and keys permanently using Hive.
///
/// Keys are stored and generated according to BIP32 standard.
/// Per default the path m/456/0/index is used for keys and dids to prove and identify the credentials someone hold.
/// If a wallet is also used to issue credentials the keypair found at path m/456/1/0  is the default one.
class WalletStore {
  Box? _keyBox;
  Box<Credential>? _credentialBox;
  Box? _configBox;
  Box<Credential>? _issuingHistory;
  Box<Connection>? _connection;

  ///The Path used to derive keys
  final String standardCredentialPath = 'm/456/0/';
  final String standardConnectionPath = 'm/456/1';

  /// Constructs a wallet at file-system path [path]
  WalletStore(String path) {
    Hive.init(path);
    try {
      Hive.registerAdapter(CredentialAdapter());
      Hive.registerAdapter(ConnectionAdapter());
    } catch (HiveError) {}
  }

  /// Opens storage containers optional encrypted with [password]
  Future<bool> openBoxes([String? password]) async {
    //password to AES-Key
    if (password != null) {
      var generator = new PBKDF2(hash: sha256);
      var aesKey = generator.generateKey(password, "salt", 1000, 32);
      //only values are encrypted, keys are stored in plaintext
      this._keyBox =
          await Hive.openBox('keyBox', encryptionCipher: HiveAesCipher(aesKey));
      this._credentialBox = await Hive.openBox<Credential>('credentialBox',
          encryptionCipher: HiveAesCipher(aesKey));
      this._configBox = await Hive.openBox('configBox',
          encryptionCipher: HiveAesCipher(aesKey));
      this._issuingHistory = await Hive.openBox<Credential>('issuingHistory',
          encryptionCipher: HiveAesCipher(aesKey));
      this._connection = await Hive.openBox<Connection>('connections',
          encryptionCipher: HiveAesCipher(aesKey));
    } else {
      this._keyBox = await Hive.openBox('keyBox');
      this._credentialBox = await Hive.openBox<Credential>('credentialBox');
      this._configBox = await Hive.openBox('configBox');
      this._issuingHistory = await Hive.openBox<Credential>('issuingHistory');
      this._connection = await Hive.openBox<Connection>('connections');
    }
    return this._keyBox != null &&
        this._issuingHistory != null &&
        this._credentialBox != null &&
        this._configBox != null &&
        this._connection != null;
  }

  bool isWalletOpen() {
    if (_keyBox == null ||
        _issuingHistory == null ||
        _credentialBox == null ||
        _configBox == null ||
        _connection == null)
      return false;
    else
      return (this._keyBox!.isOpen) &&
          (_issuingHistory!.isOpen) &&
          (this._credentialBox!.isOpen) &&
          (this._configBox!.isOpen) &&
          (this._connection!.isOpen);
  }

  //Checks whether the wallet is initialized with master-seed.
  bool isInitialized() {
    return this._keyBox!.get('seed') != null;
  }

  /// Closes Storage Containers
  Future<void> closeBoxes() async {
    await _keyBox!.close();
    await _credentialBox!.close();
    await _configBox!.close();
    await _connection!.close();
  }

  /// Initializes new hierarchical deterministic wallet or restores one from given mnemonic.
  ///
  /// Returns the used mnemonic.
  String? initialize([String? mnemonic]) {
    var mne = mnemonic;
    if (mnemonic == null) {
      mne = generateMnemonic();
    }
    var seed = mnemonicToSeed(mne!);

    this._keyBox!.put('seed', seed);
    this._keyBox!.put('lastCredentialIndex', 0);
    this._keyBox!.put('lastConnectionIndex', 0);

    return mne;
  }

  /// Generates and returns DID for the issuer.
  Future<String> initializeIssuer() async {
    var master = BIP32.fromSeed(_keyBox!.get('seed'));
    var key = master.derivePath('m/456/1/0');
    var issuerDid = await _bip32KeyToDid(key);
    _keyBox!.put('issuerDid', issuerDid);
    _credentialBox!.put(issuerDid, new Credential('m/456/1/0', '', ''));
    return issuerDid;
  }

  /// Returns the DID for issuing credentials.
  String? getStandardIssuerDid() {
    return _keyBox!.get('issuerDid');
  }

  /// Returns the private key for issuing credentials.
  String? getStandardIssuerPrivateKey() {
    return getPrivateKeyToCredentialDid(getStandardIssuerDid());
  }

  /// Lists all Credentials.
  Map<dynamic, Credential> getAllCredentials() {
    var credMap = _credentialBox!.toMap();
    return credMap;
  }

  /// Lists all Connections.
  Map<dynamic, Connection> getAllConnections() {
    var credMap = _connection!.toMap();
    return credMap;
  }

  /// Returns the credential associated with [did].
  Credential? getCredential(String? did) {
    return this._credentialBox!.get(did);
  }

  /// Returns the connection associated with [did].
  Connection? getConnection(String? did) {
    return this._connection!.get(did);
  }

  /// Stores a credential permanently.
  ///
  /// What should be stored consists of three parts
  /// - a signed credential [w3cCred] containing hashes of all attribute-values
  /// - a json structure [plaintextCred] containing hashes, salts and values per credential attribute
  /// - the [hdPath] to derive the key for the did the credential is issued for
  Future<void> storeCredential(
      String? w3cCred, String? plaintextCred, String? hdPath,
      {String? credDid}) async {
    var did;
    if (credDid == null)
      did = await getDid(hdPath!);
    else
      did = credDid;
    var tmp = new Credential(hdPath!, w3cCred!, plaintextCred!);
    await this._credentialBox!.put(did, tmp);
  }

  /// Stores a Connection permanently.
  ///
  /// What should be stored consists of three parts
  /// - the did of the communication partner [otherDid]
  /// - the [name] of the connection / the username used in this connection.
  /// - the [hdPath] to derive the key for the did of the communication
  Future<void> storeConnection(String otherDid, String name, String? hdPath,
      {String? comDid}) async {
    var did;
    if (comDid == null)
      did = await getDid(hdPath!);
    else
      did = comDid;
    var tmp = new Connection(hdPath!, otherDid, name);
    await this._connection!.put(did, tmp);
  }

  /// Stores a credential issued to [holderDid].
  void toIssuingHistory(
      String holderDid, String plaintextCredential, String w3cCredential) {
    var tmp = new Credential('', w3cCredential, plaintextCredential);
    _issuingHistory!.put(holderDid, tmp);
  }

  /// Returns a credential one issued to [holderDid].
  Credential? getIssuedCredential(String holderDid) {
    return _issuingHistory!.get(holderDid);
  }

  /// Returns all credentials one issued over time.
  Map<dynamic, Credential> getAllIssuedCredentials() {
    return _issuingHistory!.toMap();
  }

  /// Returns the last value of the next HD-path.
  int? getLastIndex() {
    return _keyBox!.get('lastCredentialIndex');
  }

  /// Returns the last value of the next HD-path for the communication keys.
  int? getLastCommunicationIndex() {
    return _keyBox!.get('lastConnectionIndex');
  }

  /// Returns a new DID a credential could be issued for.
  Future<String> getNextCredentialDID() async {
    //generate new keypair
    var master = BIP32.fromSeed(_keyBox!.get('seed'));
    var lastIndex = _keyBox!.get('lastCredentialIndex');
    var path = '$standardCredentialPath${lastIndex.toString()}';
    var key = master.derivePath(path);

    //increment derivation index
    lastIndex++;
    await _keyBox!.put('lastCredentialIndex', lastIndex);

    var did = await _bip32KeyToDid(key);

    //store temporarily
    await _configBox!.put('lastCredentialDid', did);
    await _credentialBox!.put(did, new Credential(path, '', ''));

    return did;
  }

  /// Returns a new connection-DID.
  Future<String> getNextConnectionDID() async {
    //generate new keypair
    var master = BIP32.fromSeed(_keyBox!.get('seed'));
    var lastIndex = _keyBox!.get('lastConnectionIndex');
    var path = '$standardConnectionPath${lastIndex.toString()}';
    var key = master.derivePath(path);

    //increment derivation index
    lastIndex++;
    await _keyBox!.put('lastConnectionIndex', lastIndex);

    var did = await _bip32KeyToDid(key);

    //store temporarily
    await _configBox!.put('lastConnectionDid', did);
    await _connection!.put(did, new Connection(path, '', ''));

    return did;
  }

  String? getLastCredentialDid() {
    return _configBox!.get('lastCredentialDid');
  }

  String? getLastConnectionDid() {
    return _configBox!.get('lastConnectionDid');
  }

  /// Returns the DID associated with [hdPath].
  Future<String> getDid(String hdPath) async {
    var master = BIP32.fromSeed(_keyBox!.get('seed'));
    var key = master.derivePath(hdPath);
    return await _bip32KeyToDid(key);
  }

  /// Returns the private key as hex-String associated with [hdPath].
  String getPrivateKey(String hdPath) {
    var master = BIP32.fromSeed(_keyBox!.get('seed'));
    var key = master.derivePath(hdPath);
    return HEX.encode(key.privateKey!);
  }

  /// Returns the public key as hex-String associated with [hdPath].
  String getPublicKey(String hdPath) {
    var master = BIP32.fromSeed(_keyBox!.get('seed'));
    var key = master.derivePath(hdPath);
    return HEX.encode(key.publicKey!);
  }

  /// Returns the private key as hex-String associated with [did].
  String? getPrivateKeyToCredentialDid(String? did) {
    var cred = getCredential(did);
    if (cred == null) return null;
    var master = BIP32.fromSeed(_keyBox!.get('seed'));
    var key = master.derivePath(cred.hdPath!);
    return HEX.encode(key.privateKey!);
  }

  /// Returns the private key as hex-String associated with [did].
  String? getPrivateKeyToConnectionDid(String? did) {
    var com = getConnection(did);
    if (com == null) return null;
    var master = BIP32.fromSeed(_keyBox!.get('seed'));
    var key = master.derivePath(com.hdPath!);
    return HEX.encode(key.privateKey!);
  }

  /// Stores a configuration Entry.
  void storeConfigEntry(String key, String value) {
    _configBox!.put(key, value);
  }

  /// Returns the configuration Entry for [key].
  String? getConfigEntry(String key) {
    return _configBox!.get(key);
  }

  Future<String> _bip32KeyToDid(BIP32 key) async {
    var private = EthPrivateKey.fromHex(bytesToHex(key.privateKey!));
    var addr = await private.extractAddress();
    return 'did:ethr:${addr.hexEip55}';
  }
}
