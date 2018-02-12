import 'dart:convert';

import 'utils.dart';

class IdToken {
  static String padBase64(String orig) {
    var rem = orig.length % 4;
    if (rem > 0) {
      return orig.padRight(orig.length + (4 - rem), '=');
    }

    return orig;
  }

  final JoseHeader header;
  final Map payload;
  final ClaimSet claimSet;
  final String signature;
  final String token;

  factory IdToken.fromString(String token) {
    var parts = token.split('.');
    _validate(parts.length == 3, 'id_token string should be 3 parts. '
        'Got ${parts.length} instead');

    var codec = JSON.fuse(UTF8.fuse(BASE64));
    Map header;
    Map body;
    try {
      header = codec.decode(padBase64(parts[0]));
      body = codec.decode(padBase64(parts[1]));
    } catch (e) {
      _validate(e == null, 'Error decoding id token. $e');
    }
    var claim = new ClaimSet.fromJson(body);

    // TODO(mbutler): Add Signature validation.

    return new IdToken(token,
        new JoseHeader.fromJson(header),
        body,
        claim,
        parts[2]);
  }

  IdToken(this.token, this.header, this.payload, this.claimSet, this.signature);
}

class JoseHeader {
  static const String _type = 'typ';
  static const String _cType = 'cty';
  static const String _algorithm = 'alg';
  static const String _kip = 'kip';

  final String type;
  final String contentType;
  final String algorithm;
  final String kip;
  JoseHeader.fromJson(Map json) :
        type = json[_type],
        contentType = json[_cType],
        algorithm = json[_algorithm],
        kip = json[_kip];
}

class ClaimSet {
  static const String _iss = 'iss';
  static const String _sub = 'sub';
  static const String _aud = 'aud';
  static const String _exp = 'exp';
  static const String _nbf = 'nbf';
  static const String _iat = 'iat';
  static const String _jti = 'jti';
  static const String _authTime = 'auth_time';
  static const String _nonce = 'nonce';
  static const String _acr = 'acr';
  static const String _amr = 'amr';
  static const String _azp = 'azp';


  final String issuer;
  final String subject;
  final List<String> audience;
  final DateTime expiration;
  final DateTime notBefore;
  final DateTime issuedAt;
  final DateTime authenticatedTime;
  final String nonce;
  final String authenticationContextClass;
  final String authenticationMethods;
  final String authorizedParty;
  final String jwtId;
  final Map<String, dynamic> other;

  ClaimSet._({
    this.issuer,
    this.subject,
    this.audience,
    this.jwtId,
    this.expiration,
    this.notBefore,
    this.issuedAt,
    this.authenticatedTime,
    this.nonce,
    this.authenticationContextClass,
    this.authenticationMethods,
    this.authorizedParty,
    this.other
  });

  factory ClaimSet.fromJson(Map json) {
    var iss = json.remove(_iss);
    _validate(iss != null, 'Required claim: Issuer is null');
    var sub = json.remove(_sub);
    _validate(sub != null, 'Required claim: Subject is null');
    var aud = json.remove(_aud);
    _validate(aud != null, 'Required claim: Audience is null');
    if (aud is String) {
      aud = [aud];
    }

    var expS = json.remove(_exp);
    _validate(expS != null, 'Required claim: Expiration Time is null');
    DateTime exp = dateFromSeconds(expS);

    var iatS = json.remove(_iat);
    _validate(iatS != null, 'Required claim: Issued At Time is null');
    DateTime iat = dateFromSeconds(iatS);

    var nbfS = json.remove(_nbf);
    DateTime nbf = nbfS != null ? dateFromSeconds(nbfS) : null;
    var authS = json.remove(_authTime);
    DateTime authTime = authS != null ? dateFromSeconds(authS) : null;
    var jid = json.remove(_jti);
    var nonce = json.remove(_nonce);
    var acr = json.remove(_acr);
    var amr = json.remove(_amr);
    var azp = json.remove(_azp);

    return new ClaimSet._(
        issuer: iss,
        subject: sub,
        audience: aud,
        expiration: exp,
        issuedAt: iat,
        notBefore: nbf,
        authenticatedTime: authTime,
        jwtId: jid,
        nonce: nonce,
        authenticationContextClass: acr,
        authenticationMethods: amr is List ? amr.join(",") : amr,
        authorizedParty: azp,
        other: json);
  }
}

void _validate(bool condition, String message) {
  if (condition) return;
  throw new FormatException('Invalid ID Token. $message');
}