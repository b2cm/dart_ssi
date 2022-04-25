import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:bip32/bip32.dart';
import 'package:bip39/bip39.dart';
import 'package:crypto/crypto.dart';
import 'package:dart_ssi/didcomm.dart';
import 'package:dart_web3/credentials.dart';
import 'package:dart_web3/crypto.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:ed25519_hd_key/ed25519_hd_key.dart';
import 'package:hive/hive.dart';
import 'package:x25519/x25519.dart' as x;

import '../util/private_util.dart';
import '../util/utils.dart';
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
  Box<List<dynamic>>? _exchangeHistory;
  Box<DidcommConversation>? _didcommConversations;

  ///The path used to derive credential keys
  final String standardCredentialPath = 'm/456/0/';

  ///The path used to derive connection keys
  final String standardConnectionPath = 'm/456/1';

  ///The path used to derive credential keys
  final String standardCredentialPathEd = 'm/457\'/0\'/';

  ///The path used to derive connection keys
  final String standardConnectionPathEd = 'm/457\'/1\'';

  ///The path used to derive connection keys
  final String standardConnectionPathX = 'm/457\'/2\'';

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
    if (!Hive.isAdapterRegistered(ExchangeHistoryEntryAdapter().typeId))
      Hive.registerAdapter(ExchangeHistoryEntryAdapter());
    if (!Hive.isAdapterRegistered(DidcommConversationAdapter().typeId))
      Hive.registerAdapter(DidcommConversationAdapter());
  }

  /// Opens storage containers optional encrypted with [password]
  Future<bool> openBoxes([String? password]) async {
    //password to AES-Key
    if (password != null) {
      var generator = PBKDF2(hash: sha256);
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
      _exchangeHistory = await Hive.openBox<List<dynamic>>(
          'exchangeHistory_$_nameExpansion',
          path: _walletPath,
          encryptionCipher: HiveAesCipher(aesKey));
      _didcommConversations = await Hive.openBox<DidcommConversation>(
          'didcommConversations_$_nameExpansion',
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
      _exchangeHistory = await Hive.openBox<List<dynamic>>(
          'exchangeHistory_$_nameExpansion',
          path: _walletPath);
      _didcommConversations = await Hive.openBox<DidcommConversation>(
          'didcommConversations$_nameExpansion',
          path: _walletPath);
    }
    return _keyBox != null &&
        _issuingHistory != null &&
        _credentialBox != null &&
        _configBox != null &&
        _connection != null &&
        _exchangeHistory != null &&
        _didcommConversations != null;
  }

  bool isWalletOpen() {
    if (_keyBox == null ||
        _issuingHistory == null ||
        _credentialBox == null ||
        _configBox == null ||
        _exchangeHistory == null ||
        _connection == null ||
        _didcommConversations == null)
      return false;
    else
      return (_keyBox!.isOpen) &&
          (_issuingHistory!.isOpen) &&
          (_credentialBox!.isOpen) &&
          (_configBox!.isOpen) &&
          (_exchangeHistory!.isOpen) &&
          (_connection!.isOpen) &&
          (_didcommConversations!.isOpen);
  }

  //Checks whether the wallet is initialized with master-seed.
  bool isInitialized() {
    return _keyBox!.get('seed') != null;
  }

  Map<String, Box?> getBoxes() {
    Map<String, Box> boxes = {
      "keyBox": _keyBox!,
      "credentialBox": _credentialBox!,
      "configBox": _configBox!,
      "connection": _connection!,
      "issuingHistory": _issuingHistory!,
      "didcommConversations": _didcommConversations!
    };
    return boxes;
  }

  /// Closes storage containers.
  Future<void> closeBoxes() async {
    await _keyBox!.close();
    await _credentialBox!.close();
    await _configBox!.close();
    await _connection!.close();
    await _issuingHistory!.close();
    await _exchangeHistory!.close();
    await _didcommConversations!.close();
  }

  /// Initializes new hierarchical deterministic wallet or restores one from given mnemonic.
  ///
  /// Returns the used mnemonic.
  /// If the wallet should be used with did:eth and on another ethereum-network than the mainnet,
  /// pass the nme or its id as [network].
  Future<String?> initialize(
      {String? mnemonic, String network = 'mainnet'}) async {
    var mne = mnemonic;
    if (mnemonic == null) {
      mne = generateMnemonic();
    }
    var seed = mnemonicToSeed(mne!);

    await _keyBox!.put('seed', seed);
    await _keyBox!.put('lastCredentialIndex', 0);
    await _keyBox!.put('lastConnectionIndex', 0);
    await _keyBox!.put('lastCredentialIndexEd', 0);
    await _keyBox!.put('lastConnectionIndexEd', 0);
    await _keyBox!.put('lastConnectionIndexX', 0);
    await _configBox!.put('network', network);

    return mne;
  }

  /// Generates and returns DID for the issuer.
  Future<String> initializeIssuer([KeyType keyType = KeyType.secp256k1]) async {
    if (keyType == KeyType.secp256k1) {
      var master = BIP32.fromSeed(_keyBox!.get('seed'));
      var key = master.derivePath('m/456/1/0');
      var issuerDid = await _bip32KeyToDid(key);
      await _keyBox!.put('issuerDid', issuerDid);
      await _credentialBox!.put(issuerDid, Credential('m/456/1/0', '', ''));
      return issuerDid;
    } else if (keyType == KeyType.ed25519)
      return await _initializeIssuerEdKey();
    else
      throw Exception('unknown keyType');
  }

  /// Generates and returns DID for the issuer.
  Future<String> _initializeIssuerEdKey() async {
    var key = await ED25519_HD_KEY.derivePath(
        'm/457\'/1\'/2\'', _keyBox!.get('seed').toList());
    var issuerDid = await _edKeyToDid(key);
    await _keyBox!.put('issuerDidEd', issuerDid);
    await _credentialBox!.put(issuerDid, Credential('m/457\'/1\'/2\'', '', ''));
    return issuerDid;
  }

  /// Returns the DID for issuing credentials.
  String? getStandardIssuerDid([KeyType keyType = KeyType.secp256k1]) {
    if (keyType == KeyType.secp256k1)
      return _keyBox!.get('issuerDid');
    else if (keyType == KeyType.ed25519)
      return _keyBox!.get('issuerDidEd');
    else
      throw Exception('unknown keyType');
  }

  /// Returns the private key for issuing credentials.
  Future<String?> getStandardIssuerPrivateKey(
      [KeyType keyType = KeyType.secp256k1]) async {
    var issuerDid = getStandardIssuerDid(keyType);
    if (issuerDid == null) throw Exception('Can\'t find a standard issuer did');
    return getPrivateKeyForCredentialDid(issuerDid);
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

  /// Returns the Exchange History associated with a credential identified by [credentialDid].
  List<ExchangeHistoryEntry>? getExchangeHistoryEntriesForCredential(
      String credentialDid) {
    return _exchangeHistory!.get(credentialDid)?.cast<ExchangeHistoryEntry>();
  }

  /// Stores a credential permanently.
  ///
  /// What should be stored consists of three parts
  /// - a signed credential [w3cCred] containing hashes of all attribute-values
  /// - a json structure [plaintextCred] containing hashes, salts and values per credential attribute
  /// - the [hdPath] to derive the key for the did the credential is issued for
  Future<void> storeCredential(
      String? w3cCred, String? plaintextCred, String? hdPath,
      {KeyType keyType = KeyType.secp256k1, String? credDid}) async {
    var did;
    if (credDid == null)
      did = await getDid(hdPath!, keyType);
    else
      did = credDid;
    var tmp = Credential(hdPath!, w3cCred!, plaintextCred!);
    await _credentialBox!.put(did, tmp);
  }

  /// Stores a Connection permanently.
  ///
  /// What should be stored consists of three parts
  /// - the did of the communication partner [otherDid]
  /// - the [name] of the connection / the username used in this connection.
  /// - the [hdPath] to derive the key for the did of the communication
  Future<void> storeConnection(String otherDid, String name, String? hdPath,
      {KeyType keyType = KeyType.secp256k1, String? comDid}) async {
    var did;
    if (comDid == null)
      did = await getDid(hdPath!, keyType);
    else
      did = comDid;
    var tmp = Connection(hdPath!, otherDid, name);
    await _connection!.put(did, tmp);
  }

  /// Put a new Entry to Exchange history of a credential identified by [credentialDid].
  Future<void> storeExchangeHistoryEntry(String credentialDid,
      DateTime timestamp, String action, String otherParty,
      [List<String>? shownAttributes]) async {
    List<ExchangeHistoryEntry>? existingHistoryEntries =
        getExchangeHistoryEntriesForCredential(credentialDid);
    var tmp = ExchangeHistoryEntry(
        timestamp, action, otherParty, shownAttributes ?? []);
    if (existingHistoryEntries == null) {
      await _exchangeHistory!.put(credentialDid, [tmp]);
    } else {
      await _exchangeHistory!
          .put(credentialDid, [tmp] + existingHistoryEntries);
    }
  }

  Future<void> deleteCredential(String credentialDid) async {
    await _credentialBox!.delete(credentialDid);
  }

  Future<void> deleteConnection(String connectionDid) async {
    await _connection!.delete(connectionDid);
  }

  Future<void> deleteConfigEntry(String key) async {
    await _configBox!.delete(key);
  }

  Future<void> deleteExchangeHistory(String credentialDid) async {
    await _exchangeHistory!.delete(credentialDid);
  }

  /// Stores a credential issued to [holderDid].
  void toIssuingHistory(
      String holderDid, String plaintextCredential, String w3cCredential) {
    var tmp = Credential('', w3cCredential, plaintextCredential);
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
  int? getLastCredentialIndex([KeyType keyType = KeyType.secp256k1]) {
    if (keyType == KeyType.secp256k1)
      return _keyBox!.get('lastCredentialIndex');
    else if (keyType == KeyType.ed25519)
      return _keyBox!.get('lastCredentialIndexEd');
    else
      throw Exception('Unknown KeyType');
  }

  /// Returns the last value of the next HD-path for the connection keys.
  int? getLastConnectionIndex([KeyType keyType = KeyType.secp256k1]) {
    if (keyType == KeyType.secp256k1)
      return _keyBox!.get('lastConnectionIndex');
    else if (keyType == KeyType.ed25519)
      return _keyBox!.get('lastConnectionIndexEd');
    else if (keyType == KeyType.x25519)
      return _keyBox!.get('lastConnectionIndexX');
    else
      throw Exception('Unknown KeyType');
  }

  /// Returns a new DID a credential could be issued for.
  Future<String> getNextCredentialDID(
      [KeyType keyType = KeyType.secp256k1]) async {
    if (keyType == KeyType.secp256k1)
      return _getNextCredentialDidEthr();
    else if (keyType == KeyType.ed25519)
      return _getNextCredentialDIDWithEdKey();
    else
      throw Exception('Unknown KeyType');
  }

  Future<String> _getNextCredentialDidEthr() async {
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
    await _credentialBox!.put(did, Credential(path, '', ''));

    return did;
  }

  /// Returns a new DID a credential could be issued for.
  Future<String> _getNextCredentialDIDWithEdKey() async {
    //generate new keypair
    var lastIndex = _keyBox!.get('lastCredentialIndexEd');
    var path = '$standardCredentialPathEd$lastIndex\'';
    var key =
        await ED25519_HD_KEY.derivePath(path, _keyBox!.get('seed').toList());
    var did = await _edKeyToDid(key);

    //increment derivation index
    lastIndex++;
    await _keyBox!.put('lastCredentialIndexEd', lastIndex);

    //store temporarily
    await _configBox!.put('lastCredentialDidEd', did);
    await _credentialBox!.put(did, Credential(path, '', ''));

    return did;
  }

  /// Returns a new connection-DID.
  Future<String> getNextConnectionDID(
      [KeyType keyType = KeyType.secp256k1]) async {
    if (keyType == KeyType.secp256k1)
      return _getNextConnectionDidEthr();
    else if (keyType == KeyType.ed25519)
      return _getNextConnectionDIDWithEdKey();
    else if (keyType == KeyType.x25519) {
      return _getNextConnectionDidXKey();
    } else
      throw Exception('Unknown KeyType');
  }

  Future<String> _getNextConnectionDidXKey() async {
    //generate new keypair
    var lastIndex = _keyBox!.get('lastConnectionIndexX');
    var path = '$standardCredentialPathEd$lastIndex\'';
    var key =
        await ED25519_HD_KEY.derivePath(path, _keyBox!.get('seed').toList());
    var did = await _edKeyToXKeyDid(key);

    //increment derivation index
    lastIndex++;
    await _keyBox!.put('lastConnectionIndexX', lastIndex);

    //store temporarily
    await _configBox!.put('lastConnectionDidX', did);
    await _connection!.put(did, Connection(path, '', ''));

    return did;
  }

  Future<String> _getNextConnectionDidEthr() async {
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
    await _connection!.put(did, Connection(path, '', ''));

    return did;
  }

  /// Returns a new connection-DID.
  Future<String> _getNextConnectionDIDWithEdKey() async {
    //generate new keypair
    var lastIndex = _keyBox!.get('lastConnectionIndexEd');
    var path = '$standardCredentialPathEd$lastIndex\'';
    var key =
        await ED25519_HD_KEY.derivePath(path, _keyBox!.get('seed').toList());
    var did = await _edKeyToDid(key);

    //increment derivation index
    lastIndex++;
    await _keyBox!.put('lastConnectionIndexEd', lastIndex);

    //store temporarily
    await _configBox!.put('lastConnectionDidEd', did);
    await _connection!.put(did, Connection(path, '', ''));

    return did;
  }

  String? getLastCredentialDid([KeyType keyType = KeyType.secp256k1]) {
    if (keyType == KeyType.secp256k1)
      return _configBox!.get('lastCredentialDid');
    else if (keyType == KeyType.ed25519)
      return _configBox!.get('lastCredentialDidEd');
    else
      throw Exception('Unknown KeyType');
  }

  String? getLastConnectionDid([KeyType keyType = KeyType.secp256k1]) {
    if (keyType == KeyType.secp256k1)
      return _configBox!.get('lastConnectionDid');
    else if (keyType == KeyType.ed25519)
      return _configBox!.get('lastConnectionDidEd');
    else if (keyType == KeyType.x25519)
      return _configBox!.get('lastConnectionDidX');
    else
      throw Exception('Unknown KeyType');
  }

  /// Returns the DID associated with [hdPath].
  Future<String> getDid(String hdPath,
      [KeyType keyType = KeyType.secp256k1]) async {
    if (keyType == KeyType.secp256k1) {
      var master = BIP32.fromSeed(_keyBox!.get('seed'));
      var key = master.derivePath(hdPath);
      return await _bip32KeyToDid(key);
    } else if (keyType == KeyType.ed25519) {
      var key = await ED25519_HD_KEY.derivePath(
          hdPath, _keyBox!.get('seed').toList());
      return await _edKeyToDid(key);
    } else if (keyType == KeyType.x25519) {
      var key = await ED25519_HD_KEY.derivePath(
          hdPath, _keyBox!.get('seed').toList());
      return await _edKeyToXKeyDid(key);
    } else
      throw Exception('Unknown KeyType');
  }

  /// Returns the private key as hex-String associated with [hdPath].
  Future<String> getPrivateKey(String hdPath,
      [KeyType keyType = KeyType.secp256k1]) async {
    if (keyType == KeyType.secp256k1) {
      var master = BIP32.fromSeed(_keyBox!.get('seed'));
      var key = master.derivePath(hdPath);
      return bytesToHex(key.privateKey!);
    } else if (keyType == KeyType.ed25519) {
      var key = await ED25519_HD_KEY.derivePath(
          hdPath, _keyBox!.get('seed').toList());
      return await bytesToHex(
          ed.newKeyFromSeed(Uint8List.fromList(key.key)).bytes);
    } else if (keyType == KeyType.x25519) {
      var key = await ED25519_HD_KEY.derivePath(
          hdPath, _keyBox!.get('seed').toList());
      return await bytesToHex(
          _edPrivateToXPrivate(ed.newKeyFromSeed(Uint8List.fromList(key.key))));
    } else
      throw Exception('Unknown KeyType');
  }

  Future<Map<String, dynamic>> getPrivateKeyJwk(String hdPath,
      [KeyType keyType = KeyType.secp256k1]) async {
    var privateKeyHex = await getPrivateKey(hdPath, keyType);
    var did = await getDid(hdPath, keyType);
    Map<String, dynamic> key = {};
    key['kid'] = '$did#${did.split(':').last}';
    if (keyType == KeyType.secp256k1) {
      key['kty'] = 'EC';
      key['crv'] = 'secp256k1';
      key['d'] =
          removePaddingFromBase64(base64UrlEncode(hexToBytes(privateKeyHex)));
    } else if (keyType == KeyType.x25519) {
      key['kty'] = 'OKP';
      key['crv'] = 'X25519';
      key['d'] = removePaddingFromBase64(
          base64UrlEncode(hexToBytes(privateKeyHex).sublist(0, 32)));
    } else if (keyType == KeyType.ed25519) {
      key['kty'] = 'OKP';
      key['crv'] = 'Ed25519';
      key['d'] = removePaddingFromBase64(
          base64UrlEncode(hexToBytes(privateKeyHex).sublist(0, 32)));
    } else
      throw Exception('Unknown keyType');

    return key;
  }

  /// Returns the public key as hex-String associated with [hdPath].
  Future<String> getPublicKey(String hdPath,
      [KeyType keyType = KeyType.secp256k1]) async {
    if (keyType == KeyType.secp256k1) {
      var master = BIP32.fromSeed(_keyBox!.get('seed'));
      var key = master.derivePath(hdPath);
      return bytesToHex(key.publicKey);
    } else if (keyType == KeyType.ed25519) {
      var key = await ED25519_HD_KEY.derivePath(
          hdPath, _keyBox!.get('seed').toList());
      return await bytesToHex(
          ed.public(ed.newKeyFromSeed(Uint8List.fromList(key.key))).bytes);
    } else if (keyType == KeyType.x25519) {
      var key = await ED25519_HD_KEY.derivePath(
          hdPath, _keyBox!.get('seed').toList());
      return await bytesToHex(
          _edPrivateToXPublic(ed.newKeyFromSeed(Uint8List.fromList(key.key))));
    } else
      throw Exception('Unknown KeyType');
  }

  /// Returns the private key as hex-String associated with [did].
  Future<String?> getPrivateKeyForCredentialDid(
    String did,
  ) async {
    if (did.startsWith('did:ethr'))
      return _getPrivateKeyForCredentialDidEthr(did);
    else if (did.startsWith('did:key:z6Mk'))
      return _getPrivateKeyForCredentialDidEd(did);
    else
      throw Exception('Unknown KeyType');
  }

  Future<String?> _getPrivateKeyForCredentialDidEd(String did) async {
    var cred = getCredential(did);
    if (cred == null) return null;
    var key = await ED25519_HD_KEY.derivePath(
        cred.hdPath, _keyBox!.get('seed').toList());
    return bytesToHex(ed.newKeyFromSeed(Uint8List.fromList(key.key)).bytes);
  }

  /// Returns the private key as hex-String associated with [did].
  String? _getPrivateKeyForCredentialDidEthr(String did) {
    var cred = getCredential(did);
    if (cred == null) return null;
    var master = BIP32.fromSeed(_keyBox!.get('seed'));
    var key = master.derivePath(cred.hdPath);
    return bytesToHex(key.privateKey!);
  }

  Future<Map<String, dynamic>?> getPrivateKeyForCredentialDidAsJwk(
      String did) async {
    if (did.startsWith('did:ethr')) {
      var private = await _getPrivateKeyForCredentialDidEthr(did);
      if (private == null) return null;
      Map<String, dynamic> key = {};
      key['kid'] = '$did#${did.split(':').last}';
      key['kty'] = 'EC';
      key['crv'] = 'secp256k1';
      key['d'] = removePaddingFromBase64(base64UrlEncode(hexToBytes(private)));
      return key;
    } else if (did.startsWith('did:key:z6Mk')) {
      var private = await _getPrivateKeyForCredentialDidEd(did);
      if (private == null) return null;
      Map<String, dynamic> key = {};
      key['kid'] = '$did#${did.split(':').last}';
      key['kty'] = 'OKP';
      key['crv'] = 'Ed25519';
      key['d'] = removePaddingFromBase64(
          base64UrlEncode(hexToBytes(private).sublist(0, 32)));
      return key;
    } else
      throw Exception('Unknown KeyType');
  }

  /// Returns the private key as hex-String associated with [did].
  Future<String?> getPrivateKeyForConnectionDid(String did) async {
    if (did.startsWith('did:ethr'))
      return _getPrivateKeyForConnectionDidEthr(did);
    else if (did.startsWith('did:key:z6Mk'))
      return _getPrivateKeyForConnectionDidEd(did);
    else if (did.startsWith('did:key:z6LS'))
      return _getPrivateKeyForConnectionDidX(did);
    else
      throw Exception('Unknown KeyType');
  }

  String? _getPrivateKeyForConnectionDidEthr(String did) {
    var com = getConnection(did);
    if (com == null) return null;
    var master = BIP32.fromSeed(_keyBox!.get('seed'));
    var key = master.derivePath(com.hdPath);
    return bytesToHex(key.privateKey!);
  }

  /// Returns the private key as hex-String associated with [did].
  Future<String?> _getPrivateKeyForConnectionDidEd(String did) async {
    var com = getConnection(did);
    if (com == null) return null;
    var key = await ED25519_HD_KEY.derivePath(
        com.hdPath, _keyBox!.get('seed').toList());
    return bytesToHex(ed.newKeyFromSeed(Uint8List.fromList(key.key)).bytes);
  }

  /// Returns the private key as hex-String associated with [did].
  Future<String?> _getPrivateKeyForConnectionDidX(String did) async {
    var com = getConnection(did);
    if (com == null) return null;
    var key = await ED25519_HD_KEY.derivePath(
        com.hdPath, _keyBox!.get('seed').toList());
    return bytesToHex(
        _edPrivateToXPrivate(ed.newKeyFromSeed(Uint8List.fromList(key.key))));
  }

  Future<Map<String, dynamic>?> getPrivateKeyForConnectionDidAsJwk(
      String did) async {
    if (did.startsWith('did:ethr')) {
      var private = await _getPrivateKeyForConnectionDidEthr(did);
      if (private == null) return null;
      Map<String, dynamic> key = {};
      key['kid'] = '$did#${did.split(':').last}';
      key['kty'] = 'EC';
      key['crv'] = 'secp256k1';
      key['d'] = removePaddingFromBase64(base64UrlEncode(hexToBytes(private)));
      return key;
    } else if (did.startsWith('did:key:z6Mk')) {
      var private = await _getPrivateKeyForConnectionDidEd(did);
      if (private == null) return null;
      Map<String, dynamic> key = {};
      key['kid'] = '$did#${did.split(':').last}';
      key['kty'] = 'OKP';
      key['crv'] = 'Ed25519';
      key['d'] = removePaddingFromBase64(
          base64UrlEncode(hexToBytes(private).sublist(0, 32)));
      return key;
    } else if (did.startsWith('did:key:z6LS')) {
      var private = await _getPrivateKeyForConnectionDidX(did);
      if (private == null) return null;
      Map<String, dynamic> key = {};
      key['kid'] = '$did#${did.split(':').last}';
      key['kty'] = 'OKP';
      key['crv'] = 'X25519';
      key['d'] = removePaddingFromBase64(
          base64UrlEncode(hexToBytes(private).sublist(0, 32)));
      return key;
    } else
      throw Exception('Unknown KeyType');
  }

  Future<String?> getKeyAgreementKeyForDid(String did) async {
    if (did.startsWith('did:ethr'))
      throw Exception('Could not resolve an agreement key for did:ethr');
    else if (did.startsWith('did:key:z6LS'))
      return getPrivateKeyForConnectionDid(did);
    else if (did.startsWith('did:key:z6Mk')) {
      var cred = getCredential(did);
      if (cred != null) {
        var key = await ED25519_HD_KEY.derivePath(
            cred.hdPath, _keyBox!.get('seed').toList());
        return bytesToHex(_edPrivateToXPrivate(
            ed.newKeyFromSeed(Uint8List.fromList(key.key))));
      } else {
        var con = getConnection(did);
        if (con != null) {
          var key = await ED25519_HD_KEY.derivePath(
              con.hdPath, _keyBox!.get('seed').toList());
          return bytesToHex(_edPrivateToXPrivate(
              ed.newKeyFromSeed(Uint8List.fromList(key.key))));
        } else
          throw Exception('Could not find a key for this did');
      }
    } else
      throw Exception('unsupported did');
  }

  Future<Map<String, dynamic>?> getKeyAgreementKeyForDidAsJwk(
      String did) async {
    if (did.startsWith('did:ethr'))
      throw Exception('Could not resolve an agreement key for did:ethr');
    else if (did.startsWith('did:key:z6LS'))
      return getPrivateKeyForConnectionDidAsJwk(did);
    else if (did.startsWith('did:key:z6Mk')) {
      var cred = getCredential(did);
      if (cred != null) {
        var private = await getKeyAgreementKeyForDid(did);
        if (private != null) {
          Map<String, dynamic> key = {};
          key['kid'] = '$did#${did.split(':').last}';
          key['kty'] = 'OKP';
          key['crv'] = 'X25519';
          key['d'] = removePaddingFromBase64(
              base64UrlEncode(hexToBytes(private).sublist(0, 32)));
          return key;
        }
      } else {
        var con = getConnection(did);
        if (con != null) {
          return getPrivateKeyForConnectionDidAsJwk(did);
        } else
          throw Exception('Could not find a key for this did');
      }
    } else
      throw Exception('unsupported did');
    return null;
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

  Future<String> _edKeyToDid(KeyData d) async {
    var private = ed.newKeyFromSeed(Uint8List.fromList(d.key));
    return 'did:key:z${base58Bitcoin.encode(Uint8List.fromList([
          237,
          1
        ] + ed.public(private).bytes))}';
  }

  Future<String> _edKeyToXKeyDid(KeyData data) async {
    var private = ed.newKeyFromSeed(Uint8List.fromList(data.key));

    return 'did:key:z${base58Bitcoin.encode(Uint8List.fromList([
          236,
          1
        ] + _edPrivateToXPublic(private)))}';
  }

  List<int> _edPrivateToXPrivate(ed.PrivateKey private) {
    var hash = sha512.convert(private.bytes.sublist(0, 32));
    var d = hash.bytes;
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    return d;
  }

  List<int> _edPrivateToXPublic(ed.PrivateKey private) {
    var xPublic = List.filled(32, 0);
    x.ScalarBaseMult(xPublic, _edPrivateToXPrivate(private));
    return xPublic;
  }

  DidcommConversation? getConversationEntry(String threadId) {
    return _didcommConversations!.get(threadId);
  }

  Future<void> storeConversationEntry(
      DidcommPlaintextMessage message, String myDid) async {
    var thid;
    if (message.threadId != null)
      thid = message.threadId;
    else
      thid = message.id;

    DidcommProtocol protocol;
    if (message.type.contains('issue-credential'))
      protocol = DidcommProtocol.issueCredential;
    else if (message.type.contains('present-proof'))
      protocol = DidcommProtocol.presentProof;
    else
      throw Exception('unsupported Protocol');

    await _didcommConversations!.put(
        thid, DidcommConversation(message.toString(), protocol.value, myDid));
  }
}

enum KeyType { secp256k1, ed25519, x25519 }
