import 'dart:convert';
import 'dart:math';

import 'package:mongo_dart/mongo_dart.dart';
import 'package:shelf/shelf.dart';
import 'package:crypto/crypto.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

import '../server.dart';

Middleware handleCors() {
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE',
    'Access-Control-Allow-Headers': 'Origin,Content-Type,Authorization',
  };

  return createMiddleware(
    requestHandler: (Request request) {
      if (request.method == 'OPTIONS') {
        return Response.ok('', headers: corsHeaders);
      }
      return null;
    },
    responseHandler: (Response response) {
      return response.change(headers: corsHeaders);
    },
  );
}

String generateSalt([int length = 32]) {
  final rand = Random.secure();
  final saltBytes = List<int>.generate(length, (_) => rand.nextInt(256));
  return base64.encode(saltBytes);
}

String hashPassword(String password, String salt) {
  final codec = Utf8Codec();
  final key = codec.encode(password);
  final saltBytes = codec.encode(salt);
  final hmac = Hmac(sha256, key);
  final digest = hmac.convert(saltBytes);
  return digest.toString();
}

String generateJwt(
  String subject,
  String issuer,
  String secret, {
  String? jwtId,
  Duration expiry = const Duration(seconds: 30),
}) {
  final jwt = JWT(
    {
      'iat': DateTime.now().millisecondsSinceEpoch,
    },
    subject: subject,
    issuer: issuer,
    jwtId: jwtId,
  );
  return jwt.sign(SecretKey(secret), expiresIn: expiry);
}

JWT? verifyJwt(String token, String secret) {
  try {
    return JWT.verify(token, SecretKey(secret));
  } on JWTError catch (e) {
    // JWT package bug?
    if (e.message.contains('expired')) {
      throw JWTExpiredError();
    }
    rethrow;
  }
}

Middleware handleAuth(String secret) {
  return (Handler innerHandler) {
    return (Request request) async {
      final authHeader = request.headers['Authorization'];
      var token, jwt, client;

      if (authHeader != null) {
        if (authHeader.startsWith('Bearer ')) {
          token = authHeader.substring(7);

          // Validate token
          try {
            jwt = verifyJwt(token, secret);
          } on JWTExpiredError {
            return Response.forbidden('The access token has expired.');
          } on JWTInvalidError {
            return Response(HttpStatus.badRequest,
                body: 'Refresh token is not valid');
          } on JWTError catch (e) {
            print(e);
            return Response.internalServerError(
                body: 'Failed to verify access token.');
          }
        } else if (authHeader.startsWith('Basic ')) {
          client = authHeader.substring(6);
        }
        final updatedRequest = request.change(context: {
          'authDetails': jwt ?? client,
          'userId': jwt?.subject,
        });
        return await innerHandler(updatedRequest);
      } else {
        return await innerHandler(request);
      }
    };
  };
}

Middleware checkAuthorization() {
  return createMiddleware(
    requestHandler: (Request request) {
      if (request.context['authDetails'] == null) {
        return Response.forbidden('Not authorized to perform this action.');
      }
      return null;
    },
  );
}

Middleware logUserRequests() {
  return createMiddleware(
    requestHandler: (Request req) {
      final userId = req.context['userId'];
      if (userId != null) {
        print(
            '${DateTime.now().toIso8601String()}\tuser: $userId\t${req.method}\t${req.requestedUri}');
      }
      return null;
    },
  );
}

Middleware logDbRequests() {
  return createMiddleware(
    requestHandler: (Request req) {
      final userId = req.context['userId'];
      final where = req.headers['where'];
      final operation = req.headers['operator'];
      final value = req.headers['value'];
      final orderBy = req.headers['orderBy'];
      final descending = req.headers['descending'];
      final limit = req.headers['limit'];
      var log =
          '${DateTime.now().toIso8601String()}\tuser: $userId\t/${req.url}\t';
      if (req.method == 'POST') {
        log += 'WRITE';
      } else {
        log += 'READ\tParameters: {';
        if (where != null && operation != null && value != null) {
          log += 'where: $where$operation$value,';
        }
        if (orderBy != null) {
          log += ' orderBy: $orderBy, descending: ${descending == 'true'},';
        }
        if (limit != null) {
          log += ' limit: $limit';
        }
        log += '}';
      }
      print(log);
      return null;
    },
  );
}

ObjectId parseUserId(JWT jwt) {
  return ObjectId.fromHexString(jwt.subject ?? '');
}

dynamic parseValue(String? value) {
  if (value == null) return null;
  final number = num.tryParse(value);
  if (number != null) return number;
  if (value == 'true') return true;
  if (value == 'false') return false;
  return value;
}
