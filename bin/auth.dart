import 'dart:convert';

import 'package:auth_api/server.dart';

// load variables from the .env file
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

// initiate TLS using self-signed certificate
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

  // establish connection to Redis instance
  redis = Redis(secret: SECRET, issuer: ISSUER);
  await redis.start(REDIS_IP, 6379);
  print('Token Service running...');

  // encode client_id and client_secret for HTTP Basic authentication
  var bytes = utf8.encode('$CLIENT_ID:$CLIENT_SECRET');
  clientBase64 = base64.encode(bytes);

  // encode client_id and client_secret for HTTP Basic authentication regarding the
  //local auth API, used by the Resources API to validate token
  bytes = utf8.encode('$LOCAL_CLIENT_ID:$LOCAL_CLIENT_SECRET');
  localClientBase64 = base64.encode(bytes);

  app = Router();
  appLocal = Router();
  setupRequests();
  setupLocalRequests();

  // define pipeline
  // handleAuth ensures that requests that do not pass the basic authentication
  // are dropped
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
    8443,
    securityContext: getSecurityContext(),
  );
  // Enable content compression
  server.autoCompress = true;
  print('Serving at https://${server.address.host}:${server.port}');

  serverLocal = await serve(
    handlerLocal,
    InternetAddress.anyIPv4,
    8445,
    // securityContext: getSecurityContext(),
  );
  serverLocal.autoCompress = true;
  print(
      'Locally serving at http://${serverLocal.address.host}:${serverLocal.port}');
}

void setupRequests() {
  // mount /auth requests
  app.mount(
      '/auth/',
      AuthApi(
        secret: SECRET,
        issuer: ISSUER,
        redis: redis,
        clientBase64: clientBase64,
      ).router);

  // used to test if everything is working
  app.get(
    '/hello',
    (Request request) async {
      return Response.ok('world');
    },
  );
}

void setupLocalRequests() {
  // mount /auth requests used for validating access tokens
  appLocal.mount(
      '/auth/',
      AuthLocalApi(
        secret: SECRET,
        issuer: ISSUER,
        redis: redis,
        clientBase64: localClientBase64,
      ).router);
}
