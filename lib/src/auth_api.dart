import 'dart:convert';
import 'dart:io';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf_router/shelf_router.dart';

import '../server.dart';
import 'utils.dart';

class AuthApi {
  AuthApi({
    required this.mongo,
    required this.secret,
    required this.issuer,
    required this.tokenService,
    required this.clientBase64,
  });

  final Mongo mongo;
  final String secret;
  final String issuer;
  final TokenService tokenService;
  final String clientBase64;

  Router get router {
    final router = Router();

    router.post('/register', (Request req) async {
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
            body: 'Please provide your email and password as body.');
      }
      final userInfo = json.decode(payload);
      final email = userInfo['email'];
      final password = userInfo['password'];

      print(
          '${DateTime.now().toIso8601String()}\temail: $email\tmethod: ${req.method}\turl: ${req.requestedUri}');

      // Ensure email and password fields are present
      if (email == null ||
          email.isEmpty ||
          password == null ||
          password.isEmpty) {
        return Response(HttpStatus.badRequest,
            body: 'Please make sure that email and password are not empty.');
      }

      // Ensure email is unique
      if (await mongo.hasUser(email)) {
        return Response(HttpStatus.badRequest, body: 'User already exists.');
      }

      // Create user
      await mongo.newUser(email, password);

      return Response.ok('Successfully registered user.');
    });

    router.post('/login', (Request req) async {
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
            body: 'Please provide your email and password as body.');
      }
      final userInfo = json.decode(payload);
      final email = userInfo['email'];
      final password = userInfo['password'];
      // Ensure email and password fields are present
      if (email == null ||
          email.isEmpty ||
          password == null ||
          password.isEmpty) {
        return Response(HttpStatus.badRequest,
            body: 'Please provide your email and password.');
      }

      final userId = await mongo.login(email, password);
      if (userId == null) {
        return Response(HttpStatus.badRequest,
            body: 'Incorrect user and/or password.');
      }
      print(
          '${DateTime.now().toIso8601String()}\tuser: $userId\tmethod: ${req.method}\turl: ${req.requestedUri}');

      try {
        final tokenPair = await tokenService.generateTokenPair(userId);
        return Response.ok(json.encode(tokenPair.toJson()), headers: {
          HttpHeaders.contentTypeHeader: ContentType.json.mimeType,
        });
      } catch (e) {
        return Response.internalServerError(
            body: 'There was a problem logging you in. Please try again.');
      }
    });

    router.post('/logout', (Request req) async {
      final auth = req.context['authDetails'];
      if (auth == null) {
        return Response(HttpStatus.unauthorized,
            body: 'Not authorized to perform this operation.');
      }

      try {
        final jwt = (auth as JWT);
        final jwtId = jwt.jwtId;
        final userId = jwt.subject;
        print(
            '${DateTime.now().toIso8601String()}\tuser: $userId\tmethod: ${req.method}\turl: ${req.requestedUri}');

        if (jwtId != null) {
          await tokenService.removeRefreshToken(jwtId);
        } else {
          throw Exception('jwtId is null');
        }
      } catch (e) {
        return Response.internalServerError(
            body: 'There was an issue loggin out. Please check and try again.');
      }

      return Response.ok('Successfully logged out.');
    });

    router.post('/accessToken', (Request req) async {
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
            body: 'Please provide a refresh_token.');
      }
      final Map<String, dynamic> payloadMap = json.decode(payload);
      if (!payloadMap.containsKey('refresh_token')) {
        return Response(HttpStatus.badRequest,
            body: 'Please provide a refresh_token.');
      }

      final token = payloadMap['refresh_token'];
      // Validate token
      try {
        final refreshToken = verifyJwt(token, secret);

        final tokenId = refreshToken?.jwtId;
        final userId = refreshToken?.subject;
        print(
            '${DateTime.now().toIso8601String()}\tuser: $userId\tmethod: ${req.method}\turl: ${req.requestedUri}');

        if (refreshToken == null || tokenId == null) {
          return Response(HttpStatus.badRequest,
              body: 'Refresh token is not valid.');
        }

        final dbToken = await tokenService.getRefreshToken(tokenId);
        if (dbToken == null) {
          return Response(HttpStatus.badRequest,
              body: 'Refresh token is not recognized');
        }

        // Generate new token pair - refresh access token
        try {
          if (refreshToken.subject == null || refreshToken.payload == null) {
            return Response(HttpStatus.badRequest,
                body: 'Refresh token is not recognized');
          }
          if (refreshToken.payload == null) {
            throw Exception('Cannot parse refreshToken payload');
          }
          if (!refreshToken.payload.containsKey('exp')) {
            return Response(HttpStatus.badRequest,
                body: 'Refresh token is not valid');
          }
          final expiryDate = DateTime.fromMillisecondsSinceEpoch(
              (1000 * refreshToken.payload['exp']).round());

          final tokenPair = await tokenService.refreshAccessToken(
              refreshToken.subject!, refreshToken.jwtId!, expiryDate);

          return Response.ok(
            json.encode(tokenPair.toJson()),
            headers: {
              HttpHeaders.contentTypeHeader: ContentType.json.mimeType,
            },
          );
        } catch (e) {
          print(e);
          return Response.internalServerError(
              body:
                  'There was a problem creating a new token. Please try again.');
        }
      } on JWTExpiredError {
        return Response.forbidden('The refresh token has expired.');
      } on JWTInvalidError {
        return Response(HttpStatus.badRequest,
            body: 'Refresh token is not valid');
      } on JWTError catch (e) {
        print(e);
        return Response.internalServerError(
            body: 'Failed to verify refresh token.');
      }
    });

    return router;
  }
}
