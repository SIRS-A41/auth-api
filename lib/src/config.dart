import 'package:envify/envify.dart';

part 'config.g.dart';

@Envify()
abstract class Env {
  static const secretKey = _Env.secretKey;
  static const issuer = _Env.issuer;
  static const clientId = _Env.clientId;
  static const clientSecret = _Env.clientSecret;
  static const localClientId = _Env.localClientId;
  static const localClientSecret = _Env.localClientSecret;
  static const redisIp = _Env.redisIp;
}
