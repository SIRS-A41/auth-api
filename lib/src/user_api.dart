import 'dart:convert';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'mongo.dart';

import 'utils.dart';

import 'package:shelf/shelf.dart';
import 'package:shelf_router/shelf_router.dart';

class UserApi {
  final Mongo mongo;
  UserApi({required this.mongo});
  Handler get router {
    final router = Router();

    router.get('/', (Request req) async {
      final authDetails = req.context['authDetails'] as JWT;
      final userId = parseUserId(authDetails);
      final user = await mongo.getUser(userId);
      return Response.ok(
          json.encode(
            {
              'email': user!['email'],
              'userId': userId,
            },
          ),
          headers: {
            'content-type': 'application/json',
          });
    });

    final handler =
        Pipeline().addMiddleware(checkAuthorization()).addHandler(router);

    return handler;
  }
}
