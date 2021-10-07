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
  String _walletPath;
  late String _nameExpansion;
  Box? _keyBox;
  Box<Credential>? _credentialBox;
  Box? _configBox;
  Box<Credential>? _issuingHistory;
  Box<Connection>? _connection;

  ///The path used to derive credential keys
  final String standardCredentialPath = 'm/456/0/';

  ///The path used to derive connection keys
  final String standardConnectionPath = 'm/456/1';

  /// Constructs a wallet at file-system path [path].
  WalletStore(this._walletPath) {
    Hive.init(_walletPath);
    _nameExpansion = _walletPath.replaceAll('/', '_');
    var split = _nameExpansion.split('_');
    if (split.length > 3) {
      _nameExpansion =
          '${split[split.length - 3]}${split[split.length - 2]}${split[split.length - 1]}';
    }
    if (!Hive.isAdapterRegistered(CredentialAdapter().typeId))
      Hive.registerAdapter(CredentialAdapter());
    if (!Hive.isAdapterRegistered(ConnectionAdapter().typeId))
      Hive.registerAdapter(ConnectionAdapter());
  }

  /// Opens storage containers optional encrypted with [password]
  Future<bool> openBoxes([String? password]) async {
    //password to AES-Key
    if (password != null) {
      var generator = new PBKDF2(hash: sha256);
      var aesKey = generator.generateKey(password, "salt", 1000, 32);
      //only values are encrypted, keys are stored in plaintext
      _keyBox = await Hive.openBox('keyBox_$_nameExpansion',
          path: _walletPath, encryptionCipher: HiveAesCipher(aesKey));
      _credentialBox = await Hive.openBox<Credential>(
          'credentialBox_$_nameExpansion',
          path: _walletPath,
          encryptionCipher: HiveAesCipher(aesKey));
      _configBox = await Hive.openBox('configBox_$_nameExpansion',
          path: _walletPath, encryptionCipher: HiveAesCipher(aesKey));
      _issuingHistory = await Hive.openBox<Credential>(
          'issuingHistory_$_nameExpansion',
          path: _walletPath,
          encryptionCipher: HiveAesCipher(aesKey));
      _connection = await Hive.openBox<Connection>(
          'connections_$_nameExpansion',
          path: _walletPath,
          encryptionCipher: HiveAesCipher(aesKey));
    } else {
      _keyBox = await Hive.openBox('keyBox_$_nameExpansion', path: _walletPath);
      _credentialBox = await Hive.openBox<Credential>(
          'credentialBox_$_nameExpansion',
          path: _walletPath);
      _configBox =
          await Hive.openBox('configBox_$_nameExpansion', path: _walletPath);
      _issuingHistory = await Hive.openBox<Credential>(
          'issuingHistory_$_nameExpansion',
          path: _walletPath);
      _connection = await Hive.openBox<Connection>(
          'connections_$_nameExpansion',
          path: _walletPath);
    }
    return _keyBox != null &&
        _issuingHistory != null &&
        _credentialBox != null &&
        _configBox != null &&
        _connection != null;
  }

  bool isWalletOpen() {
    if (_keyBox == null ||
        _issuingHistory == null ||
        _credentialBox == null ||
        _configBox == null ||
        _connection == null)
      return false;
    else
      return (_keyBox!.isOpen) &&
          (_issuingHistory!.isOpen) &&
          (_credentialBox!.isOpen) &&
          (_configBox!.isOpen) &&
          (_connection!.isOpen);
  }

  //Checks whether the wallet is initialized with master-seed.
  bool isInitialized() {
    return _keyBox!.get('seed') != null;
  }

  /// Closes storage containers.
  Future<void> closeBoxes() async {
    await _keyBox!.close();
    await _credentialBox!.close();
    await _configBox!.close();
    await _connection!.close();
    await _issuingHistory!.close();
  }

  /// Initializes new hierarchical deterministic wallet or restores one from given mnemonic.
  ///
  /// Returns the used mnemonic.
  /// If the wallet should be used on another ethereum-network than the mainnet,
  /// pass the nme or its id as [network].
  String? initialize({String? mnemonic, String network = 'mainnet'}) {
    var mne = mnemonic;
    if (mnemonic == null) {
      mne = generateMnemonic();
    }
    var seed = mnemonicToSeed(mne!);

    _keyBox!.put('seed', seed);
    _keyBox!.put('lastCredentialIndex', 0);
    _keyBox!.put('lastConnectionIndex', 0);
    _configBox!.put('network', network);

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
    return getPrivateKeyForCredentialDid(getStandardIssuerDid());
  }

  /// Lists all credentials.
  Map<dynamic, Credential> getAllCredentials() {
    var credMap = _credentialBox!.toMap();
    return credMap;
  }

  /// Lists all connections.
  Map<dynamic, Connection> getAllConnections() {
    var connMap = _connection!.toMap();
    return connMap;
  }

  /// Returns the credential associated with [did].
  Credential? getCredential(String? did) {
    return _credentialBox!.get(did);
  }

  /// Returns the connection associated with [did].
  Connection? getConnection(String? did) {
    return _connection!.get(did);
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
    await _credentialBox!.put(did, tmp);
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
    await _connection!.put(did, tmp);
  }

  Future<void> deleteCredential(String credentialDid) async {
    await _credentialBox!.delete(credentialDid);
  }

  Future<void> deleteConnection(String connectionDid) async {
    await _connection!.delete(connectionDid);
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

  /// Returns the last value of the next HD-path for the credential keys.
  int? getLastIndex() {
    return _keyBox!.get('lastCredentialIndex');
  }

  /// Returns the last value of the next HD-path for the connection keys.
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
    return HEX.encode(key.publicKey);
  }

  /// Returns the private key as hex-String associated with [did].
  String? getPrivateKeyForCredentialDid(String? did) {
    var cred = getCredential(did);
    if (cred == null) return null;
    var master = BIP32.fromSeed(_keyBox!.get('seed'));
    var key = master.derivePath(cred.hdPath);
    return HEX.encode(key.privateKey!);
  }

  /// Returns the private key as hex-String associated with [did].
  String? getPrivateKeyForConnectionDid(String? did) {
    var com = getConnection(did);
    if (com == null) return null;
    var master = BIP32.fromSeed(_keyBox!.get('seed'));
    var key = master.derivePath(com.hdPath);
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
    String network = _configBox!.get('network') as String;
    if (network == 'mainnet')
      return 'did:ethr:${addr.hexEip55}';
    else
      return 'did:ethr:$network:${addr.hexEip55}';
  }
}
