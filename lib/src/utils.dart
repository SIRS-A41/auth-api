import 'dart:convert';
import 'dart:math';

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

// generate randomly secure salt
String generateSalt([int length = 32]) {
  final rand = Random.secure();
  final saltBytes = List<int>.generate(length, (_) => rand.nextInt(256));
  return base64.encode(saltBytes);
}

// hash password using SHA-512
String hashPassword(String password, String salt) {
  final codec = Utf8Codec();
  final key = codec.encode(password);
  final saltBytes = codec.encode(salt);
  final hmac = Hmac(sha512, key);
  final digest = hmac.convert(saltBytes);
  return digest.toString();
}

// generate JWT
String generateJwt(
  String subject,
  String issuer,
  String secret, {
  String? jwtId,
  Duration expiry = const Duration(seconds: 30),
}) {
  final jwt = JWT(
    {
      // store the timestamp of when it was issued
      'iat': DateTime.now().millisecondsSinceEpoch,
    },
    // owner of access token
    subject: subject,
    // issuers name
    issuer: issuer,
    // id of token
    jwtId: jwtId,
  );
  // sign JWT using secret and set expiry date
  return jwt.sign(SecretKey(secret), expiresIn: expiry);
}

JWT? verifyJwt(String token, String secret) {
  try {
    // verify JWT token
    return JWT.verify(token, SecretKey(secret));
  } on JWTError catch (e) {
    // JWT package bug?
    if (e.message.contains('expired')) {
      throw JWTExpiredError();
    } else if (e.message.contains('invalid')) {
      throw JWTInvalidError(e.message.split(': ').last);
    }
    rethrow;
  }
}

Middleware handleAuth(String secret) {
  return (Handler innerHandler) {
    return (Request request) async {
      final authHeader = request.headers['Authorization'];
      var client;

      // check if request has Authorization header
      if (authHeader != null) {
        // pass the client details
        if (authHeader.startsWith('Basic ')) {
          client = authHeader.substring(6);
        }
        final updatedRequest = request.change(context: {
          'authDetails': client,
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
      // if no authorization was provided, reject request
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
