import 'dart:convert';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

import '../server.dart';

class AuthLocalApi {
  AuthLocalApi({
    required this.secret,
    required this.issuer,
    required this.redis,
    required this.clientBase64,
  });

  final String secret;
  final String issuer;
  final Redis redis;
  final String clientBase64;

  Router get router {
    final router = Router();

    router.post('/validate', (Request req) async {
      // verify client_id and client_secret
      final _clientBase64 = req.context['authDetails'];
      if (_clientBase64 == null) {
        return Response(HttpStatus.badRequest,
            body: 'Provide client_id and client_secret.');
      }
      if (_clientBase64 != clientBase64) {
        return Response.forbidden('Incorrect client_id and/or client_secret.');
      }

      final payload = await req.readAsString();
      if (payload.isEmpty) {
        return Response(HttpStatus.badRequest,
            body: 'Please provide an access_token.');
      }
      final Map<String, dynamic> payloadMap = json.decode(payload);
      if (!payloadMap.containsKey('access_token')) {
        return Response(HttpStatus.badRequest,
            body: 'Please provide a access_token.');
      }

      final token = payloadMap['access_token'];
      var jwt;
      // Validate token
      try {
        jwt = verifyJwt(token, secret);
      } on JWTExpiredError {
        return Response.forbidden('The access token has expired.');
      } on JWTInvalidError {
        return Response(HttpStatus.badRequest,
            body: 'Refresh token is not valid');
      } on JWTError {
        return Response.internalServerError(
            body: 'Failed to verify access token.');
      }

      final userId = jwt.subject;
      if (userId == null) {
        return Response.forbidden('Not authorized to perform this action. 2');
      }
      if (await redis.hasUser(userId)) {
        return Response.ok(userId);
      } else {
        return Response.forbidden('Not authorized to perform this action. 3');
      }
    });

    return router;
  }
}
