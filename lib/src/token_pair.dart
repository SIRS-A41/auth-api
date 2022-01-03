class TokenPair {
  TokenPair(this.idToken, this.refreshToken, this.expiry, this.refreshExpiry);

  final String idToken;
  final String refreshToken;
  final int expiry;
  final int refreshExpiry;

  Map<String, dynamic> toJson() => {
        'access_token': idToken,
        'token_type': 'bearer',
        'expires_in': expiry,
        'refresh_token': refreshToken,
        'refresh_token_expires_in': refreshExpiry,
      };
}
