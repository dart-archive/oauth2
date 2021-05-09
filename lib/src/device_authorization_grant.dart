// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'package:http_parser/http_parser.dart';
import 'package:http/http.dart' as http;

import '../oauth2.dart';
import '../oauth2.dart';
import 'credentials.dart';
import 'handle_access_token_response.dart';
import 'parameters.dart';
import 'utils.dart';

const _expirationGrace = Duration(seconds: 10);

/// A class for obtaining credentials via an [device authorization grant][].
///
/// FIXME update
/// This method of authorization involves sending the resource owner to the
/// authorization server where they will authorize the client. They're then
/// redirected back to your server, along with an authorization code. This is
/// used to obtain [Credentials] and create a fully-authorized [Client].
///
/// FIXME update
/// To use this class, you must first call [getAuthorizationUrl] to get the URL
/// to which to redirect the resource owner. Then once they've been redirected
/// back to your application, call [handleAuthorizationResponse] or
/// [handleAuthorizationCode] to process the authorization server's response and
/// construct a [Client].
///
/// [device code grant]: https://tools.ietf.org/html/rfc8628#section-1
class DeviceAuthorizationGrant {
  /// The function used to parse parameters from a host's response.
  final GetParameters _getParameters;

  /// The client identifier for this client.
  ///
  /// The authorization server will issue each client a separate client
  /// identifier and secret, which allows the server to tell which client is
  /// accessing it. Some servers may also have an anonymous identifier/secret
  /// pair that any client may use.
  ///
  /// This is usually global to the program using this library.
  final String identifier;

  /// The client secret for this client.
  ///
  /// The authorization server will issue each client a separate client
  /// identifier and secret, which allows the server to tell which client is
  /// accessing it. Some servers may also have an anonymous identifier/secret
  /// pair that any client may use.
  ///
  /// This is usually global to the program using this library.
  ///
  /// Note that clients whose source code or binary executable is readily
  /// available may not be able to make sure the client secret is kept a secret.
  /// This is fine; OAuth2 servers generally won't rely on knowing with
  /// certainty that a client is who it claims to be.
  final String? secret;

  /// A URL provided by the authorization server that this library uses to
  /// obtain a device_code.
  ///
  /// This will usually be listed in the authorization server's OAuth2 API
  /// documentation.
  final Uri deviceEndpoint;

  /// A URL provided by the authorization server that this library uses to
  /// obtain long-lasting credentials.
  ///
  /// This will usually be listed in the authorization server's OAuth2 API
  /// documentation.
  final Uri tokenEndpoint;

  /// Callback to be invoked whenever the credentials are refreshed.
  ///
  /// This will be passed as-is to the constructed [Client].
  final CredentialsRefreshedCallback? _onCredentialsRefreshed;

  /// Whether to use HTTP Basic authentication for authorizing the client.
  final bool _basicAuth;

  /// A [String] used to separate scopes; defaults to `" "`.
  final String _delimiter;

  /// The HTTP client used to make HTTP requests.
  http.Client? _httpClient;

  /// The scopes that the client is requesting access to.
  List<String>? _scopes;

  /// The current state of the grant object.
  _State _state = _State.initial;

  /// The deviceId
  String? _deviceCode;

  /// Creates a new grant.
  ///
  /// If [basicAuth] is `true` (the default), the client credentials are sent to
  /// the server using using HTTP Basic authentication as defined in [RFC 2617].
  /// Otherwise, they're included in the request body. Note that the latter form
  /// is not recommended by the OAuth 2.0 spec, and should only be used if the
  /// server doesn't support Basic authentication.
  ///
  /// [RFC 2617]: https://tools.ietf.org/html/rfc2617
  ///
  /// [httpClient] is used for all HTTP requests made by this grant, as well as
  /// those of the [Client] is constructs.
  ///
  /// [onCredentialsRefreshed] will be called by the constructed [Client]
  /// whenever the credentials are refreshed.
  ///
  /// The scope strings will be separated by the provided [delimiter]. This
  /// defaults to `" "`, the OAuth2 standard, but some APIs (such as Facebook's)
  /// use non-standard delimiters.
  ///
  /// By default, this follows the OAuth2 spec and requires the server's
  /// responses to be in JSON format. However, some servers return non-standard
  /// response formats, which can be parsed using the [getParameters] function.
  ///
  /// This function is passed the `Content-Type` header of the response as well
  /// as its body as a UTF-8-decoded string. It should return a map in the same
  /// format as the [standard JSON response][].
  ///
  /// [standard JSON response]: https://tools.ietf.org/html/rfc6749#section-5.1
  DeviceAuthorizationGrant(
    this.identifier,
    this.deviceEndpoint,
    this.tokenEndpoint, {
    this.secret,
    String? delimiter,
    bool basicAuth = true,
    http.Client? httpClient,
    CredentialsRefreshedCallback? onCredentialsRefreshed,
    Map<String, dynamic> Function(MediaType? contentType, String body)?
        getParameters,
  })  : _basicAuth = basicAuth,
        _httpClient = httpClient ?? http.Client(),
        _delimiter = delimiter ?? ' ',
        _getParameters = getParameters ?? parseJsonParameters,
        _onCredentialsRefreshed = onCredentialsRefreshed;

  /// FIXME documentation
  Future<DeviceProperties> getDeviceCode({Iterable<String>? scopes}) async {
    if (_state != _State.initial) {
      throw StateError('The device_code has already been generated.');
    }

    var scopeList = scopes?.toList() ?? <String>[];
    _scopes = scopeList;

    var headers = <String, String>{};
    var body = <String, String>{};

    var secret = this.secret;
    if (_basicAuth && secret != null) {
      headers['Authorization'] = basicAuthHeader(identifier, secret);
    } else {
      // The ID is required for this request any time basic auth isn't being
      // used, even if there's no actual client authentication to be done.
      body['client_id'] = identifier;
      if (secret != null) body['client_secret'] = secret;
    }

    if (scopeList.isNotEmpty) body['scope'] = scopeList.join(_delimiter);

    var startTime = DateTime.now();

    var response =
        await _httpClient!.post(deviceEndpoint, headers: headers, body: body);

    var device_properties = _handleDeviceCodeResponse(
        response, startTime, _scopes,
        getParameters: _getParameters);

    _state = _State.polling;

    return device_properties;
  }

  /// Check if the user has confirmed the device and then return a [Client]
  Future<Client> pollForToken() async {
    if (_state == _State.initial) {
      throw StateError('The device_code has not yet been generated.');
    } else if (_state == _State.finished) {
      throw StateError('The device has already been authorized.');
    }

    var startTime = DateTime.now();

    var headers = <String, String>{};
    var body = {
      'device_code': _deviceCode,
      'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
    };

    var secret = this.secret;
    if (_basicAuth && secret != null) {
      headers['Authorization'] = basicAuthHeader(identifier, secret);
    } else {
      // The ID is required for this request any time basic auth isn't being
      // used, even if there's no actual client authentication to be done.
      body['client_id'] = identifier;
      if (secret != null) body['client_secret'] = secret;
    }

    var response =
        await _httpClient!.post(tokenEndpoint, headers: headers, body: body);

    var credentials = handleAccessTokenResponse(
        response, tokenEndpoint, startTime, _scopes, _delimiter,
        getParameters: _getParameters);

    _state = _State.finished;

    return Client(
      credentials,
      identifier: identifier,
      secret: secret,
      basicAuth: _basicAuth,
      httpClient: _httpClient,
      onCredentialsRefreshed: _onCredentialsRefreshed,
    );
  }

  DeviceProperties _handleDeviceCodeResponse(
      http.Response response, DateTime startTime, List<String>? scopes,
      {Map<String, dynamic> Function(MediaType? contentType, String body)?
          getParameters}) {
    getParameters ??= parseJsonParameters;

    try {
      if (response.statusCode != 200) {
        // TODO handle ErrorResponse
      }

      var contentTypeString = response.headers['content-type'];
      if (contentTypeString == null) {
        throw FormatException('Missing Content-Type string.');
      }

      var parameters =
          getParameters(MediaType.parse(contentTypeString), response.body);

      /// Required parameters according to https://tools.ietf.org/html/rfc8628#section-3.2
      for (var requiredParameter in [
        'device_code',
        'user_code',
        'verification_uri'
      ]) {
        if (!parameters.containsKey(requiredParameter)) {
          throw FormatException(
              'did not contain required parameter "$requiredParameter"');
        } else if (parameters[requiredParameter] is! String) {
          throw FormatException(
              'required parameter "$requiredParameter" was not a string, was '
              '"${parameters[requiredParameter]}"');
        }
      }

      var expiresIn = parameters['expires_in'];
      if (expiresIn == null || expiresIn is! int) {
        print(expiresIn is String);
        throw FormatException(
            'parameter "expires_in" was not an int, was "$expiresIn"');
      }

      for (var name in ['device_code', 'user_code']) {
        var value = parameters[name];
        if (value != null && value is! String) {
          throw FormatException(
              'parameter "$name" was not a string, was "$value"');
        }
      }

      var verificationUri = parameters['verification_uri'];
      if (verificationUri != null) {
        try {
          Uri.parse(verificationUri);
        } on FormatException {
          throw FormatException(
              'parameter "verification_uri" was not a string, was "$verificationUri"');
        }
      }

      _deviceCode = parameters['device_code'];
      return DeviceProperties(
          parameters['device_code'],
          parameters['user_code'],
          parameters['verification_uri'],
          parameters['verification_uri_complete'],
          parameters['expires_in'],
          startTime.add(Duration(seconds: parameters['expires_in'])),
          parameters['interval']);
    } on FormatException catch (e) {
      throw FormatException('Invalid OAuth response for "$deviceEndpoint": '
          '${e.message}.\n\n${response.body}');
    }
  }

  /// Closes the grant and frees its resources.
  ///
  /// This will close the underlying HTTP client, which is shared by the
  /// [Client] created by this grant, so it's not safe to close the grant and
  /// continue using the client.
  void close() {
    _httpClient?.close();
    _httpClient = null;
  }
}

/// Response values of the device_code request
class DeviceProperties {
  final String device_code;
  final String user_code;
  final String verification_uri;
  final String? verification_uri_complete;
  final int expires_in;
  final DateTime expires;
  final int? interval;

  const DeviceProperties(
      this.device_code,
      this.user_code,
      this.verification_uri,
      this.verification_uri_complete,
      this.expires_in,
      this.expires,
      this.interval);
}

/// State that [ Device Authorization Grant] can be in
class _State {
  /// [DeviceAuthorizationGrant.getDeviceCode] has not yet been called for
  /// this grant.
  static const initial = _State('initial');

  /// [DeviceAuthorizationGrant.getDeviceCode] has been called but the device
  /// wasn't authorized by the user.
  static const polling = _State('polling');

  /// [DeviceAuthorizationGrant.getDeviceCode] has been called and the device
  /// was authorized by the user.
  static const finished = _State('finished');

  final String _name;

  const _State(this._name);

  @override
  String toString() => _name;
}
