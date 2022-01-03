import 'dart:convert';

import '../lib/server.dart';

const SECRET = Env.secretKey;
const ISSUER = Env.issuer;
const CLIENT_ID = Env.clientId;
const CLIENT_SECRET = Env.clientSecret;

late HttpServer server;
late Mongo mongo;
late TokenService tokenService;
late Router app;
late String clientBase64;

void main(List<String> arguments) async {
  mongo = Mongo('mongodb://localhost:27017');
  await mongo.init();

  print(ISSUER);
  tokenService = TokenService(secret: SECRET, issuer: ISSUER);
  await tokenService.start('localhost', 6379);
  print('Token Service running...');

  var bytes = utf8.encode('$CLIENT_ID:$CLIENT_SECRET');
  clientBase64 = base64.encode(bytes);

  app = Router();
  setupRequests();

  final handler = Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(handleCors())
      .addMiddleware(handleAuth(SECRET))
      .addMiddleware(logUserRequests())
      .addHandler(app);
  server = await serve(
    handler,
    InternetAddress.anyIPv4,
    8080,
    //securityContext: SecurityContext.defaultContext,
  );
  // Enable content compression
  server.autoCompress = true;

  print('Serving at http://${server.address.host}:${server.port}');
}

void setupRequests() {
  app.mount(
      '/auth/',
      AuthApi(
        mongo: mongo,
        secret: SECRET,
        issuer: ISSUER,
        tokenService: tokenService,
        clientBase64: clientBase64,
      ).router);
  app.mount('/user/', UserApi(mongo: mongo).router);
  app.mount('/db/', DbApi(mongo: mongo).router);

  app.get(
    '/hello',
    (Request request) async {
      return Response.ok('world');
    },
  );
}
