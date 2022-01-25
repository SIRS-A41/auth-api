import 'dart:convert';

import 'package:auth_api/server.dart';

const SECRET = Env.secretKey;
const ISSUER = Env.issuer;
const CLIENT_ID = Env.clientId;
const CLIENT_SECRET = Env.clientSecret;
const LOCAL_CLIENT_ID = Env.localClientId;
const LOCAL_CLIENT_SECRET = Env.localClientSecret;
const REDIS_IP = Env.redisIp;

late HttpServer server;
late HttpServer serverLocal;
late Redis redis;
late Router app;
late Router appLocal;
late String clientBase64;
late String localClientBase64;

SecurityContext getSecurityContext() {
  // Bind with a secure HTTPS connection
  final chain =
      Platform.script.resolve('../certificates/cert.pem').toFilePath();
  final key = Platform.script.resolve('../certificates/key.pem').toFilePath();

  return SecurityContext()
    ..useCertificateChain(chain)
    ..usePrivateKey(key, password: 'changeit');
}

void main(List<String> arguments) async {
  print(ISSUER);
  redis = Redis(secret: SECRET, issuer: ISSUER);
  await redis.start(REDIS_IP, 6379);
  print('Token Service running...');

  var bytes = utf8.encode('$CLIENT_ID:$CLIENT_SECRET');
  clientBase64 = base64.encode(bytes);

  bytes = utf8.encode('$LOCAL_CLIENT_ID:$LOCAL_CLIENT_SECRET');
  localClientBase64 = base64.encode(bytes);

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
    // 8000,
    8443,
    securityContext: getSecurityContext(),
  );
  // Enable content compression
  server.autoCompress = true;

  print('Serving at https://${server.address.host}:${server.port}');

  serverLocal = await serve(
    handlerLocal,
    InternetAddress.anyIPv4,
    // 8080,
    8445,
    // securityContext: getSecurityContext(),
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

  app.get(
    '/hello',
    (Request request) async {
      return Response.ok('world');
    },
  );
}

void setupLocalRequests() {
  appLocal.mount(
      '/auth/',
      AuthLocalApi(
        secret: SECRET,
        issuer: ISSUER,
        redis: redis,
        clientBase64: localClientBase64,
      ).router);
}
