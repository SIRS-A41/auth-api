import 'dart:convert';

import 'token_pair.dart';
import 'package:redis_dart/redis_dart.dart';

import 'utils.dart';
import 'package:uuid/uuid.dart';

const ACCESS_TOKEN_EXPIRY = Duration(minutes: 5);
const REFRESH_TOKEN_EXPIRY = Duration(days: 365);

class Redis {
  Redis({required this.secret, required this.issuer});

  late RedisClient _db;
  final String secret;
  final String issuer;

  final String _tokenPrefix = 'tokens';
  final String _userPrefix = 'users';

  Future<void> start(String host, int port) async {
    _db = await RedisClient.connect(host, port);
  }

  // Generate token pair = refresh token + access token
  Future<TokenPair> generateTokenPair(String userId,
      {DateTime? resfreshExpiryDate}) async {
    final tokenId = Uuid().v4();
    final token = generateJwt(userId, issuer, secret,
        jwtId: tokenId, expiry: ACCESS_TOKEN_EXPIRY);

    final refreshExpiry =
        resfreshExpiryDate?.difference(DateTime.now().toUtc()) ??
            REFRESH_TOKEN_EXPIRY;
    final refreshToken = generateJwt(
      userId,
      issuer,
      secret,
      jwtId: tokenId,
      expiry: refreshExpiry,
    );
    await addRefreshToken(tokenId, refreshToken, refreshExpiry);

    return TokenPair(token, refreshToken, ACCESS_TOKEN_EXPIRY.inMinutes,
        refreshExpiry.inMinutes);
  }

  // Refresh access token
  Future<TokenPair> refreshAccessToken(
      String userId, String tokenId, DateTime expiryDate) async {
    final tokenPair =
        await generateTokenPair(userId, resfreshExpiryDate: expiryDate);
    await removeRefreshToken(tokenId);
    return tokenPair;
  }

  Future<void> addRefreshToken(String id, String token, Duration expiry) async {
    await _db.set('$_tokenPrefix:$id', token);
    await _db.expire('$_tokenPrefix:$id', expiry);
  }

  Future<dynamic> getRefreshToken(String id) async {
    return (await _db.get('$_tokenPrefix:$id')).value;
  }

  Future<void> removeRefreshToken(String id) async {
    await _db.delete('$_tokenPrefix:$id');
  }

  Future<bool> hasUser(String username) async {
    return (await _db.exists('$_userPrefix:$username')).value;
  }

  Future<void> newUser(String username, String password) async {
    final salt = generateSalt();
    final hashedPassword = hashPassword(password, salt);
    await _db.set(
      '$_userPrefix:$username',
      jsonEncode({
        'password': hashedPassword,
        'salt': salt,
      }),
    );
  }

  Future<String?> login(String username, String password) async {
    final data = (await _db.get('$_userPrefix:$username')).value;
    if (data == null) return null;

    final user = jsonDecode(data);

    final hashedPassword = hashPassword(password, user['salt']);

    if (hashedPassword != user['password']) {
      return null;
    }
    return username;
  }
}
