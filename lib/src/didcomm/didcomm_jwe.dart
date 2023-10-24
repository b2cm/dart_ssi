import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:crypto_keys/crypto_keys.dart';
import 'package:dart_ssi/src/dids/did_document.dart';
import 'package:dart_ssi/src/wallet/wallet_store.dart';
import 'package:elliptic/ecdh.dart' as ecdh;
import 'package:elliptic/elliptic.dart' as elliptic;
import 'package:json_schema/json_schema.dart';
import 'package:web3dart/crypto.dart';
import 'package:x25519/x25519.dart' as x25519;

import '../util/types.dart';
import '../util/utils.dart';
import 'didcomm_jwm.dart';
import 'didcomm_jws.dart';
import 'types.dart';

var encryptedMessageSchema = JsonSchema.create({
  'type': 'object',
  'properties': {
    'ciphertext': {'type': 'string'},
    'tag': {'type': 'string'},
    'protected': {'type': 'string'},
    'unprotected': {'type': 'string'},
    'aad': {'type': 'string'},
    'iv': {'type': 'string'},
    'recipients': {
      'type': 'array',
      'contains': {
        'type': 'object',
        'properties': {
          'encrypted_key': {'type': 'string'},
          'header': {'type': 'object'}
        },
        'required': ['encrypted_key']
      }
    }
  },
  'required': ['ciphertext', 'recipients', 'iv', 'tag']
});

bool isEncryptedMessage(dynamic message) {
  var asMap = credentialToMap(message);
  return encryptedMessageSchema.validate(asMap).isValid;
}

///A didcomm encrypted message
class DidcommEncryptedMessage implements JsonObject, DidcommMessage {
  late String protectedHeader;
  late String tag;
  late String iv;
  late String ciphertext;
  late List<dynamic> recipients;
  String? protectedHeaderApu;
  String? protectedHeaderApv;
  String? protectedHeaderAlg;
  String? protectedHeaderSkid;
  Map<String, dynamic>? protectedHeaderEpk;
  String? protectedHeaderEnc;

  DidcommEncryptedMessage(
      {required this.protectedHeader,
      required this.tag,
      required this.iv,
      required this.ciphertext,
      required this.recipients});

  DidcommEncryptedMessage.fromJson(dynamic message) {
    Map<String, dynamic> decoded = credentialToMap(message);
    ciphertext = decoded['ciphertext']!;
    iv = decoded['iv']!;
    tag = decoded['tag']!;
    recipients = decoded['recipients']! as List;
    protectedHeader = decoded['protected']!;
    _decodeProtected();
  }

  DidcommEncryptedMessage.fromPlaintext(
      {KeyWrapAlgorithm keyWrapAlgorithm = KeyWrapAlgorithm.ecdh1PU,
      EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.a256cbc,
      required Map<String, dynamic> senderPrivateKeyJwk,
      required List<Map<String, dynamic>> recipientPublicKeyJwk,
      required DidcommMessage plaintext}) {
    Map<String, dynamic> jweHeader = {};
    jweHeader['enc'] = encryptionAlgorithm.value;
    jweHeader['alg'] = keyWrapAlgorithm.value;
    if (keyWrapAlgorithm == KeyWrapAlgorithm.ecdh1PU) {
      jweHeader['apu'] = removePaddingFromBase64(
          base64UrlEncode(utf8.encode(senderPrivateKeyJwk['kid'])));
    }
    jweHeader['skid'] = senderPrivateKeyJwk['kid'];
    String curve = senderPrivateKeyJwk['crv']!;
    String keyType = senderPrivateKeyJwk['kty']!;

    List<String> receiverKeyIds = [];
    for (Map<String, dynamic> key in recipientPublicKeyJwk) {
      if (key['crv'] == curve) {
        receiverKeyIds.add(key['kid']);
      }
    }
    receiverKeyIds.sort();
    String keyIdString = '';
    for (var keyId in receiverKeyIds) {
      keyIdString += '$keyId.';
    }
    if (keyIdString.isEmpty) {
      throw Exception('Cant find keys with matching crv parameter');
    }
    keyIdString = keyIdString.substring(0, keyIdString.length - 1);
    var apv = removePaddingFromBase64(
        base64UrlEncode(sha256.convert(utf8.encode(keyIdString)).bytes));
    jweHeader['apv'] = apv;

    //1) Resolve dids to get public keys

    //important: KeyAgreement section in diddoc
    //apu = key-id of sender (first entry in keyAgreementArray) -> entry istsef (if did) or id of key-Object

    //apv: get all key-ids in KeyAgreement _> search which match curve of sender key -> sort alphanumerical -> concat with . -> sha256 -> base64URL

    //2) look for Key-Type and generate Ephermal Key

    elliptic.Curve? c;
    Object epkPrivate;
    List<int> epkPublic = [];
    if (curve.startsWith('P') || curve.startsWith('secp256k1')) {
      if (curve == 'P-256') {
        c = elliptic.getP256();
      } else if (curve == 'P-384') {
        c = elliptic.getP384();
      } else if (curve == 'P-521') {
        c = elliptic.getP521();
      } else if (curve == 'secp256k1') {
        c = elliptic.getSecp256k1();
      } else {
        throw UnimplementedError();
      }

      epkPrivate = c.generatePrivateKey();
    } else if (curve.startsWith('X')) {
      var eKeyPair = x25519.generateKeyPair();
      epkPrivate = eKeyPair.privateKey;
      epkPublic = eKeyPair.publicKey;
    } else {
      throw UnimplementedError();
    }

    Map<String, dynamic> epkJwk = {'kty': keyType, 'crv': curve};
    if (epkPrivate is elliptic.PrivateKey) {
      epkJwk['x'] = removePaddingFromBase64(
          base64UrlEncode(intToBytes(epkPrivate.publicKey.X)));
      epkJwk['y'] = removePaddingFromBase64(
          base64UrlEncode(intToBytes(epkPrivate.publicKey.Y)));
    } else if (epkPrivate is List<int>) {
      epkJwk['x'] = removePaddingFromBase64(base64UrlEncode(epkPublic));
    } else {
      throw Exception('Unknown Key type');
    }
    jweHeader['epk'] = epkJwk;

    //3) generate symmetric CEK
    SymmetricKey cek;
    if (encryptionAlgorithm == EncryptionAlgorithm.a256cbc) {
      cek = SymmetricKey.generate(512);
    } else {
      cek = SymmetricKey.generate(256);
    }
    Encrypter e;
    if (encryptionAlgorithm == EncryptionAlgorithm.a256cbc) {
      e = cek.createEncrypter(algorithms.encryption.aes.cbcWithHmac.sha512);
    } else if (encryptionAlgorithm == EncryptionAlgorithm.a256gcm) {
      e = cek.createEncrypter(algorithms.encryption.aes.gcm);
    } else {
      throw UnimplementedError();
    }

    //4) Generate IV

    //5) build aad ( ASCII(BASE64URL(UTF8(JWE Protected Header))) )
    var aad = ascii.encode(removePaddingFromBase64(
        base64UrlEncode(utf8.encode(jsonEncode(jweHeader)))));
    //6) encrypt and get tag
    var encrypted = e.encrypt(
        Uint8List.fromList(utf8.encode(plaintext.toString())),
        additionalAuthenticatedData: aad);

    // 7) Encrypt cek for all recipients
    List<Map<String, dynamic>> recipients = [];
    for (var key in recipientPublicKeyJwk) {
      if (key['crv'] == curve) {
        Map<String, dynamic> r = {};
        r['header'] = {'kid': key['kid']};
        var encryptedCek = _encryptSymmetricKey(
            cek, keyWrapAlgorithm.value, curve, key, epkPrivate, apv,
            c: c,
            senderPrivateKeyJwk: senderPrivateKeyJwk,
            tag: encrypted.authenticationTag);
        r['encrypted_key'] =
            removePaddingFromBase64(base64UrlEncode(encryptedCek.data));
        recipients.add(r);
      }
    }

    //9) put everything together

    protectedHeader = ascii.decode(aad);
    tag =
        removePaddingFromBase64(base64UrlEncode(encrypted.authenticationTag!));
    iv = removePaddingFromBase64(
        base64UrlEncode(encrypted.initializationVector!));
    ciphertext = removePaddingFromBase64(base64UrlEncode(encrypted.data));
    this.recipients = recipients;
  }

  /// Decrypt this encrypted message using keys from [wallet].
  Future<DidcommMessage> decrypt(WalletStore wallet,
      {Future<DidDocument> Function(String) didResolver =
          resolveDidDocument}) async {
    _decodeProtected();
    if (protectedHeaderAlg!.startsWith('ECDH-1PU')) {
      if (protectedHeaderSkid == null) {
        throw Exception('sender id needed when using AuthCrypt');
      }
      var senderDDO = (await didResolver(protectedHeaderSkid!.split('#').first))
          .resolveKeyIds()
          .convertAllKeysToJwk();
      for (var key in senderDDO.keyAgreement!) {
        if (key is VerificationMethod) {
          if (key.publicKeyJwk!['kid'] == protectedHeaderSkid ||
              key.id == protectedHeaderSkid) {
            return decryptWithJwk(
                await _searchPrivateKey(wallet), key.publicKeyJwk);
          }
        }
      }
      throw Exception('No key found in did document');
    } else if (protectedHeaderAlg!.startsWith('ECDH-ES')) {
      return decryptWithJwk(await _searchPrivateKey(wallet));
    } else {
      throw Exception('Unknown algorithm');
    }
  }

  Future<Map<String, dynamic>> _searchPrivateKey(WalletStore wallet) async {
    var didsTried = [];
    for (var entry in recipients) {
      String kid = entry['header']['kid']!;
      var did = kid.split('#').first;
      didsTried.add(did);
      var key = await wallet.getKeyAgreementKeyForDidAsJwk(did);
      if (key != null) {
        return key;
      } else {
        key = await wallet.getPrivateKeyForConnectionDidAsJwk(did);
        if (key != null) return key;
      }
    }
    throw Exception('No Key found in the wallet for following '
        'dids: ${didsTried.isNotEmpty ? didsTried.join(', ') : 'none due to '
            'recipient in message'}');
  }

  DidcommMessage decryptWithJwk(Map<String, dynamic> privateKeyJwk,
      [Map<String, dynamic>? senderPublicKeyJwk]) {
    _decodeProtected();

    var crv = privateKeyJwk['crv'];
    elliptic.Curve? c;
    dynamic receiverPrivate, epkPublic;

    if (crv.startsWith('P') || crv.startsWith('secp256k1')) {
      if (crv == 'P-256') {
        c = elliptic.getP256();
      } else if (crv == 'P-384') {
        c = elliptic.getP384();
      } else if (crv == 'P-521') {
        c = elliptic.getP521();
      } else if (crv == 'secp256k1') {
        c = elliptic.getSecp256k1();
      } else {
        throw UnimplementedError("Curve `$crv` not supported");
      }

      receiverPrivate = elliptic.PrivateKey(
          c,
          bytesToUnsignedInt(
              base64Decode(addPaddingToBase64(privateKeyJwk['d']))));
      epkPublic = elliptic.PublicKey.fromPoint(
          c,
          elliptic.AffinePoint.fromXY(
              bytesToUnsignedInt(
                  base64Decode(addPaddingToBase64(protectedHeaderEpk!['x']))),
              bytesToUnsignedInt(
                  base64Decode(addPaddingToBase64(protectedHeaderEpk!['y'])))));
    } else if (crv.startsWith('X')) {
      receiverPrivate = base64Decode(addPaddingToBase64(privateKeyJwk['d']));
      epkPublic = base64Decode(addPaddingToBase64(protectedHeaderEpk!['x']));
    } else {
      throw UnimplementedError("Curve `$crv` not supported");
    }

    //2) compute shared Secret
    List<int> sharedSecret;
    bool authcrypt = false;
    if (protectedHeaderAlg!.startsWith('ECDH-ES')) {
      sharedSecret =
          _ecdhES(receiverPrivate, epkPublic, apv: protectedHeaderApv);
    } else if (protectedHeaderAlg!.startsWith('ECDH-1PU')) {
      authcrypt = true;
      if (senderPublicKeyJwk == null) {
        throw Exception('Public key of sender needed');
      }
      //var senderDid = base64Decode(addPaddingToBase64(apu));
      Object senderPubKey;
      if (crv.startsWith('P') || crv.startsWith('secp256k1')) {
        senderPubKey = elliptic.PublicKey.fromPoint(
            c!,
            elliptic.AffinePoint.fromXY(
                bytesToUnsignedInt(
                    base64Decode(addPaddingToBase64(senderPublicKeyJwk['x']))),
                bytesToUnsignedInt(base64Decode(
                    addPaddingToBase64(senderPublicKeyJwk['y'])))));
      } else if (crv.startsWith('X')) {
        senderPubKey =
            base64Decode(addPaddingToBase64(senderPublicKeyJwk['x']));
      } else {
        throw UnimplementedError("Curve `$crv` is not supported");
      }

      sharedSecret = _ecdh1PU(
          receiverPrivate,
          receiverPrivate,
          epkPublic,
          senderPubKey,
          base64Decode(addPaddingToBase64(tag)),
          protectedHeaderAlg!,
          protectedHeaderApu!,
          protectedHeaderApv!);
    } else {
      throw UnimplementedError("Algorithm `${protectedHeaderAlg!}`"
          " is not supported");
    }
    //3) Decrypt cek

    //a)search encrypted cek
    String encryptedCek = '';
    for (var entry in recipients) {
      var kid = entry['header']['kid']!;
      if (kid == privateKeyJwk['kid']) {
        encryptedCek = entry['encrypted_key'];
        break;
      }
    }

    Map<String, dynamic> sharedSecretJwk = {
      'kty': 'oct',
      'k': base64UrlEncode(sharedSecret)
    };

    var keyWrapKey = KeyPair.fromJwk(sharedSecretJwk);
    Encrypter kw = keyWrapKey.publicKey!
        .createEncrypter(algorithms.encryption.aes.keyWrap);
    var decryptedCek = kw.decrypt(
        EncryptionResult(base64Decode(addPaddingToBase64(encryptedCek))));
    var cek = SymmetricKey(keyValue: decryptedCek);
    //4) Decrypt Body
    Encrypter e;
    if (protectedHeaderEnc! == 'A256CBC-HS512') {
      e = cek.createEncrypter(algorithms.encryption.aes.cbcWithHmac.sha512);
    } else if (protectedHeaderEnc == 'A256GCM') {
      e = cek.createEncrypter(algorithms.encryption.aes.gcm);
    } else {
      throw UnimplementedError();
    }

    var toDecrypt = EncryptionResult(
        base64Decode(addPaddingToBase64(ciphertext)),
        authenticationTag: base64Decode(addPaddingToBase64(tag)),
        additionalAuthenticatedData: ascii.encode(protectedHeader),
        initializationVector: base64Decode(addPaddingToBase64(iv)));

    var plain = e.decrypt(toDecrypt);
    //5)return body
    DidcommMessage m;
    Map message = jsonDecode(utf8.decode(plain));

    if (message.containsKey('id')) {
      m = DidcommPlaintextMessage.fromJson(message);
      m as DidcommPlaintextMessage;
      if (authcrypt) {
        if (m.from != null) {
          if (m.from != protectedHeaderSkid!.split('#').first) {
            throw Exception(
                'From value of plaintext Message do not match skid of encrypted message');
          }
        } else {
          throw Exception(
              'from header in plaintext message is required if authcrypt is used');
        }
      }
    } else if (message.containsKey('ciphertext')) {
      m = DidcommSignedMessage.fromJson(message);
    } else if (message.containsKey('signatures')) {
      m = DidcommEncryptedMessage.fromJson(message);
    } else {
      throw Exception('Unknown Message type');
    }

    return m;
  }

  @override
  Map<String, dynamic> toJson() {
    return {
      'ciphertext': ciphertext,
      'protected': protectedHeader,
      'tag': tag,
      'iv': iv,
      'recipients': recipients
    };
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }

  _decodeProtected() {
    Map<String, dynamic> protectedJson = jsonDecode(
        utf8.decode(base64Decode(addPaddingToBase64(protectedHeader))));
    if (protectedJson.containsKey('alg')) {
      protectedHeaderAlg = protectedJson['alg'];
    }
    if (protectedJson.containsKey('epk')) {
      protectedHeaderEpk = protectedJson['epk'];
    }
    if (protectedJson.containsKey('apv')) {
      protectedHeaderApv = protectedJson['apv'];
    }
    if (protectedJson.containsKey('skid')) {
      protectedHeaderSkid = protectedJson['skid'];
    }
    if (protectedJson.containsKey('enc')) {
      protectedHeaderEnc = protectedJson['enc'];
    }
    if (protectedJson.containsKey('apu')) {
      protectedHeaderApu = protectedJson['apu'];
      protectedHeaderSkid ??=
          utf8.decode(base64Decode(addPaddingToBase64(protectedHeaderApu!)));
    }
  }

  EncryptionResult _encryptSymmetricKey(
      SymmetricKey symmetricKey,
      String keyWrapAlgorithm,
      String curve,
      Map<String, dynamic> publicKeyJwk,
      dynamic epkPrivate,
      String apv,
      {Map<String, dynamic>? senderPrivateKeyJwk,
      List<int>? tag,
      elliptic.Curve? c}) {
    //7) do ecdh to get shared Secret
    List<int> sharedSecret;
    if (keyWrapAlgorithm.startsWith('ECDH-ES')) {
      if (curve.startsWith('P')) {
        var ePubKey = elliptic.PublicKey(
            c!,
            bytesToUnsignedInt(
                base64Decode(addPaddingToBase64(publicKeyJwk['x']!))),
            bytesToUnsignedInt(
                base64Decode(addPaddingToBase64(publicKeyJwk['y']!))));

        sharedSecret = _ecdhES(epkPrivate, ePubKey, apv: apv);
      } else if (curve.startsWith('X')) {
        sharedSecret = _ecdhES(
            epkPrivate, base64Decode(addPaddingToBase64(publicKeyJwk['x']!)),
            apv: apv);
      } else {
        throw UnimplementedError();
      }
    } else if (keyWrapAlgorithm.startsWith('ECDH-1PU')) {
      Object staticKeyPrivate, pub;
      if (curve.startsWith('P') || curve.startsWith('secp256k1')) {
        staticKeyPrivate = elliptic.PrivateKey(
            c!,
            bytesToUnsignedInt(
                base64Decode(addPaddingToBase64(senderPrivateKeyJwk!['d']!))));
        pub = elliptic.PublicKey(
            c,
            bytesToUnsignedInt(
                base64Decode(addPaddingToBase64(publicKeyJwk['x']!))),
            bytesToUnsignedInt(
                base64Decode(addPaddingToBase64(publicKeyJwk['y']!))));
      } else if (curve.startsWith('X')) {
        staticKeyPrivate =
            base64Decode(addPaddingToBase64(senderPrivateKeyJwk!['d']!));
        pub = base64Decode(addPaddingToBase64(publicKeyJwk['x']!));
      } else {
        throw UnimplementedError();
      }

      sharedSecret = _ecdh1PU(
          epkPrivate,
          staticKeyPrivate,
          pub,
          pub,
          tag!,
          keyWrapAlgorithm,
          removePaddingFromBase64(
              base64Encode(utf8.encode(senderPrivateKeyJwk['kid']))),
          apv);
    } else {
      throw UnimplementedError();
    }

    Map<String, dynamic> sharedSecretJwk = {
      'kty': 'oct',
      'k': base64UrlEncode(sharedSecret)
    };

    //8) Encrypt CEK with Key Wrap algo
    var keyWrapKey = KeyPair.fromJwk(sharedSecretJwk);
    Encrypter kw = keyWrapKey.publicKey!
        .createEncrypter(algorithms.encryption.aes.keyWrap);
    return kw.encrypt(symmetricKey.keyValue);
  }

  List<int> _ecdhES(dynamic privateKey, dynamic publicKey,
      {String? apu, String? apv}) {
    List<int> z;
    if (privateKey is elliptic.PrivateKey && publicKey is elliptic.PublicKey) {
      z = ecdh.computeSecret(privateKey, publicKey);
    } else if (privateKey is List<int> && publicKey is List<int>) {
      z = x25519.X25519(privateKey, publicKey);
    } else {
      throw Exception('Unknown key-Type');
    }

    //Didcomm only uses A256KW
    var keyDataLen = 256;
    var suppPubInfo = _int32BigEndianBytes(keyDataLen);

    var encAscii = ascii.encode('ECDH-ES+A256KW');
    var encLength = _int32BigEndianBytes(encAscii.length);

    List<int> partyU, partyULength;
    if (apu != null) {
      partyU = base64Decode(addPaddingToBase64(apu));
      partyULength = _int32BigEndianBytes(partyU.length);
    } else {
      partyU = [];
      partyULength = _int32BigEndianBytes(0);
    }

    List<int> partyV, partyVLength;
    if (apv != null) {
      partyV = base64Decode(addPaddingToBase64(apv));
      partyVLength = _int32BigEndianBytes(partyV.length);
    } else {
      partyV = [];
      partyVLength = _int32BigEndianBytes(0);
    }

    var otherInfo = encLength +
        encAscii +
        partyULength +
        partyU +
        partyVLength +
        partyV +
        suppPubInfo;

    var kdfIn = [0, 0, 0, 1] + z + otherInfo;
    var digest = sha256.convert(kdfIn);
    return digest.bytes;
  }

  List<int> _ecdh1PU(
      dynamic private1,
      dynamic private2,
      dynamic public1,
      dynamic public2,
      List<int> tag,
      String keyWrapAlgorithm,
      String apu,
      String apv) {
    List<int> ze, zs;

    if (private1 is elliptic.PrivateKey &&
        private2 is elliptic.PrivateKey &&
        public1 is elliptic.PublicKey &&
        public2 is elliptic.PublicKey) {
      ze = ecdh.computeSecret(private1, public1);
      zs = ecdh.computeSecret(private2, public2);
    } else if (private1 is List<int> &&
        private2 is List<int> &&
        public1 is List<int> &&
        public2 is List<int>) {
      ze = x25519.X25519(private1, public1);
      zs = x25519.X25519(private2, public2);
    } else {
      throw Exception('Unknown Key-Type');
    }
    var z = ze + zs;

    //Didcomm only uses A256KW
    var keyDataLen = 256;
    var cctagLen = _int32BigEndianBytes(tag.length);
    var suppPubInfo = _int32BigEndianBytes(keyDataLen) + cctagLen + tag;

    var encAscii = ascii.encode(keyWrapAlgorithm);
    var encLength = _int32BigEndianBytes(encAscii.length);

    var partyU = base64Decode(addPaddingToBase64(apu));
    var partyULength = _int32BigEndianBytes(partyU.length);

    var partyV = base64Decode(addPaddingToBase64(apv));
    var partyVLength = _int32BigEndianBytes(partyV.length);

    var otherInfo = encLength +
        encAscii +
        partyULength +
        partyU +
        partyVLength +
        partyV +
        suppPubInfo;

    var kdfIn = [0, 0, 0, 1] + z + otherInfo;
    var digest = sha256.convert(kdfIn);

    return digest.bytes;
  }

  Uint8List _int32BigEndianBytes(int value) =>
      Uint8List(4)..buffer.asByteData().setInt32(0, value, Endian.big);
}
