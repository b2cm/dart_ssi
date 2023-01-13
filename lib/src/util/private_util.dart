import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:crypto/crypto.dart';
import 'package:x25519/src/curve25519.dart' as x25519;

// Reference https://github.com/marceloneppel/pbkdf2/blob/master/lib/pbkdf2_dart.dart
class PBKDF2 {
  Hash? hash;
  final List<int> _blockList = [1, 1, 1, 1];
  int? _prfLengthInBytes;

  PBKDF2({this.hash});

  List<int> generateKey(String password, String salt, int c, int dkLen) {
    if (dkLen > (2 << 31 - 1) * prfLengthInBytes!) {
      throw "derived key too long";
    }

    var numberOfBlocks = (dkLen / prfLengthInBytes!).ceil();
    var sizeOfLastBlock = dkLen - (numberOfBlocks - 1) * prfLengthInBytes!;

    var key = <int>[];
    for (var i = 1; i <= numberOfBlocks; ++i) {
      var block = _computeBlock(password, salt, c, i);
      if (i < numberOfBlocks) {
        key.addAll(block);
      } else {
        key.addAll(block.sublist(0, sizeOfLastBlock));
      }
    }
    return key;
  }

  int? get prfLengthInBytes {
    if (_prfLengthInBytes != null) {
      return _prfLengthInBytes;
    }

    var digest = hash!.convert([1, 2, 3]);
    var digestLength = digest.bytes.length;
    return digestLength;
  }

  List<int> _computeBlock(
      String password, String salt, int iterations, int blockNumber) {
    var hmac = Hmac(hash!, password.codeUnits);
    var sink = SyncChunkedConversionSink();
    var outsink = hmac.startChunkedConversion(sink);

    outsink.add(salt.codeUnits);

    _writeBlockNumber(outsink, blockNumber);

    outsink.close();
    sink.close();

    var bytes = sink.getAll();
    var lastDigest = bytes;
    List<int> result = List.from(bytes);

    for (var i = 1; i < iterations; i++) {
      hmac = Hmac(hash!, password.codeUnits);
      var newDigest = hmac.convert(lastDigest);

      _xorLists(result, newDigest.bytes);

      lastDigest = newDigest.bytes;
    }

    return result;
  }

  void _writeBlockNumber(ByteConversionSink hmac, int blockNumber) {
    _blockList[0] = blockNumber >> 24;
    _blockList[1] = blockNumber >> 16;
    _blockList[2] = blockNumber >> 8;
    _blockList[3] = blockNumber;
    hmac.add(_blockList);
  }

  void _xorLists(List<int> list1, List<int> list2) {
    for (var i = 0; i < list1.length; i++) {
      list1[i] = list1[i] ^ list2[i];
    }
  }
}

class SyncChunkedConversionSink extends ChunkedConversionSink<Digest> {
  final List<Digest> accumulated = <Digest>[];

  @override
  void add(Digest chunk) {
    accumulated.add(chunk);
  }

  @override
  void close() {}

  List<int> getAll() =>
      accumulated.fold([], (acc, current) => acc..addAll(current.bytes));
}

//ported from https://github.com/oasisprotocol/ed25519/blob/master/extra/x25519/x25519.go
String ed25519PublicToX25519Public(List<int> ed25519Public) {
  var Y = x25519.FieldElement();
  x25519.feFromBytes(Y, ed25519Public);
  var oneMinusY = x25519.FieldElement();
  x25519.FeOne(oneMinusY);
  x25519.FeSub(oneMinusY, oneMinusY, Y);
  x25519.feInvert(oneMinusY, oneMinusY);

  var outX = x25519.FieldElement();
  x25519.FeOne(outX);
  x25519.FeAdd(outX, outX, Y);

  x25519.feMul(outX, outX, oneMinusY);

  var dst = List.filled(32, 0);
  x25519.FeToBytes(dst, outX);

  const xMultiCodec = [236, 1];

  return base58Bitcoin.encode(Uint8List.fromList(xMultiCodec + dst));
}
