import 'dart:convert';

import 'package:auth_api/server.dart';

const SECRET = Env.secretKey;
const ISSUER = Env.issuer;
const CLIENT_ID = Env.clientId;
const CLIENT_SECRET = Env.clientSecret;

late HttpServer server;
late HttpServer serverLocal;
late Redis redis;
late Router app;
late Router appLocal;
late String clientBase64;

void main(List<String> arguments) async {
  print(ISSUER);
  redis = Redis(secret: SECRET, issuer: ISSUER);
  await redis.start('localhost', 6379);
  print('Token Service running...');

  var bytes = utf8.encode('$CLIENT_ID:$CLIENT_SECRET');
  clientBase64 = base64.encode(bytes);

  app = Router();
  appLocal = Router();
  setupRequests();
  setupLocalRequests();

  final handler = Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(handleCors())
      .addMiddleware(handleAuth(SECRET))
      .addMiddleware(logUserRequests())
      .addHandler(app);
  final handlerLocal = Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(handleCors())
      .addMiddleware(handleAuth(SECRET))
      .addMiddleware(logUserRequests())
      .addHandler(appLocal);

  server = await serve(
    handler,
    InternetAddress.anyIPv4,
    8000,
  );
  // Enable content compression
  server.autoCompress = true;

  print('Serving at http://${server.address.host}:${server.port}');

  serverLocal = await serve(
    handlerLocal,
    InternetAddress.anyIPv4,
    8080,
  );
  serverLocal.autoCompress = true;
  print(
      'Locally serving at http://${serverLocal.address.host}:${serverLocal.port}');
}

void setupRequests() {
  app.mount(
      '/auth/',
      AuthApi(
        secret: SECRET,
        issuer: ISSUER,
        redis: redis,
        clientBase64: clientBase64,
      ).router);
}

void setupLocalRequests() {
  appLocal.mount(
      '/auth/',
      AuthLocalApi(
        secret: SECRET,
        issuer: ISSUER,
        redis: redis,
        clientBase64: clientBase64,
      ).router);
}
