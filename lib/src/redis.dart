import 'dart:convert';

import 'token_pair.dart';
import 'package:redis_dart/redis_dart.dart';

import 'utils.dart';
import 'package:uuid/uuid.dart';

// access tokens expire after 5 minutes (can be adjusted)
const ACCESS_TOKEN_EXPIRY = Duration(minutes: 5);

// refresh tokens expire after 365 days (can be adjusted)
const REFRESH_TOKEN_EXPIRY = Duration(days: 365);

class Redis {
  Redis({required this.secret, required this.issuer});

  late RedisClient _db;
  final String secret;
  final String issuer;

  final String _tokenPrefix = 'tokens';
  final String _userPrefix = 'users';

  // start connection to Redis instance
  Future<void> start(String host, int port) async {
    _db = await RedisClient.connect(host, port);
  }

  // Generate token pair = refresh token + access token
  Future<TokenPair> generateTokenPair(String userId,
      {DateTime? resfreshExpiryDate}) async {
    // generate unique id
    final tokenId = Uuid().v4();

    // generate access token
    // tokenId indicates the refresh_token it corresponds to
    final token = generateJwt(userId, issuer, secret,
        jwtId: tokenId, expiry: ACCESS_TOKEN_EXPIRY);

    // set refresh token expiry date
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
    // store refresh token
    await addRefreshToken(tokenId, refreshToken, refreshExpiry);

    // return token pair
    return TokenPair(token, refreshToken, ACCESS_TOKEN_EXPIRY.inMinutes,
        refreshExpiry.inMinutes);
  }

  // Refresh access token
  Future<TokenPair> refreshAccessToken(
      String userId, String tokenId, DateTime expiryDate) async {
    // generate new token pair
    final tokenPair =
        await generateTokenPair(userId, resfreshExpiryDate: expiryDate);

    // remove old refresh token
    await removeRefreshToken(tokenId);

    return tokenPair;
  }

  Future<void> addRefreshToken(String id, String token, Duration expiry) async {
    // add refresh token to Redis and add expiry
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
    // check if Redis has user
    return (await _db.exists('$_userPrefix:$username')).value;
  }

  Future<void> newUser(String username, String password) async {
    // generate salt
    final salt = generateSalt();
    // hash password with salt
    final hashedPassword = hashPassword(password, salt);
    // add username, hashed password, and salt to database
    await _db.set(
      '$_userPrefix:$username',
      jsonEncode({
        'password': hashedPassword,
        'salt': salt,
      }),
    );
  }

  Future<String?> login(String username, String password) async {
    // get user data
    final data = (await _db.get('$_userPrefix:$username')).value;
    if (data == null) return null;

    final user = jsonDecode(data);

    // hash password provided by the user with the corresponding salt
    final hashedPassword = hashPassword(password, user['salt']);

    // check if stored password matches the provided one
    if (hashedPassword != user['password']) {
      return null;
    }
    return username;
  }
}
