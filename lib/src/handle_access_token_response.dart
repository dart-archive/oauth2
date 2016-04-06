// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http_parser/http_parser.dart';

import 'credentials.dart';
import 'authorization_exception.dart';

/// The amount of time to add as a "grace period" for credential expiration.
///
/// This allows credential expiration checks to remain valid for a reasonable
/// amount of time.
const _expirationGrace = const Duration(seconds: 10);

/// Handles a response from the authorization server that contains an access
/// token.
///
/// This response format is common across several different components of the
/// OAuth2 flow.
Credentials handleAccessTokenResponse(
    http.Response response,
    Uri tokenEndpoint,
    DateTime startTime,
    List<String> scopes) {
  if (response.statusCode != 200) _handleErrorResponse(response, tokenEndpoint);

  validate(condition, message) =>
      _validate(response, tokenEndpoint, condition, message);

  var contentType = response.headers['content-type'];
  if (contentType != null) contentType = new MediaType.parse(contentType);

  // The spec requires a content-type of application/json, but some endpoints
  // (e.g. Dropbox) serve it as text/javascript instead.
  validate(contentType != null &&
      (contentType.mimeType == "application/json" ||
       contentType.mimeType == "text/javascript"),
      'content-type was "$contentType", expected "application/json"');

  var parameters;
  try {
    parameters = JSON.decode(response.body);
  } on FormatException {
    validate(false, 'invalid JSON');
  }

  for (var requiredParameter in ['access_token', 'token_type']) {
    validate(parameters.containsKey(requiredParameter),
        'did not contain required parameter "$requiredParameter"');
    validate(parameters[requiredParameter] is String,
        'required parameter "$requiredParameter" was not a string, was '
        '"${parameters[requiredParameter]}"');
  }

  // TODO(nweiz): support the "mac" token type
  // (http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01)
  validate(parameters['token_type'].toLowerCase() == 'bearer',
      '"$tokenEndpoint": unknown token type "${parameters['token_type']}"');

  var expiresIn = parameters['expires_in'];
  validate(expiresIn == null || expiresIn is int,
      'parameter "expires_in" was not an int, was "$expiresIn"');

  for (var name in ['refresh_token', 'scope']) {
    var value = parameters[name];
    validate(value == null || value is String,
        'parameter "$name" was not a string, was "$value"');
  }

  var scope = parameters['scope'];
  if (scope != null) scopes = scope.split(" ");

  var expiration = expiresIn == null ? null :
      startTime.add(new Duration(seconds: expiresIn) - _expirationGrace);

  return new Credentials(
      parameters['access_token'],
      refreshToken: parameters['refresh_token'],
      tokenEndpoint: tokenEndpoint,
      scopes: scopes,
      expiration: expiration);
}

/// Throws the appropriate exception for an error response from the
/// authorization server.
void _handleErrorResponse(http.Response response, Uri tokenEndpoint) {
  validate(condition, message) =>
      _validate(response, tokenEndpoint, condition, message);

  // OAuth2 mandates a 400 or 401 response code for access token error
  // responses. If it's not a 400 reponse, the server is either broken or
  // off-spec.
  if (response.statusCode != 400 && response.statusCode != 401) {
    var reason = '';
    if (response.reasonPhrase != null && !response.reasonPhrase.isEmpty) {
      ' ${response.reasonPhrase}';
    }
    throw new FormatException('OAuth request for "$tokenEndpoint" failed '
        'with status ${response.statusCode}$reason.\n\n${response.body}');
  }

  var contentType = response.headers['content-type'];
  if (contentType != null) contentType = new MediaType.parse(contentType);
  validate(contentType != null && contentType.mimeType == "application/json",
      'content-type was "$contentType", expected "application/json"');

  var parameters;
  try {
    parameters = JSON.decode(response.body);
  } on FormatException {
    validate(false, 'invalid JSON');
  }

  validate(parameters.containsKey('error'),
      'did not contain required parameter "error"');
  validate(parameters["error"] is String,
      'required parameter "error" was not a string, was '
      '"${parameters["error"]}"');

  for (var name in ['error_description', 'error_uri']) {
    var value = parameters[name];
    validate(value == null || value is String,
        'parameter "$name" was not a string, was "$value"');
  }

  var description = parameters['error_description'];
  var uriString = parameters['error_uri'];
  var uri = uriString == null ? null : Uri.parse(uriString);
  throw new AuthorizationException(parameters['error'], description, uri);
}

void _validate(
    http.Response response,
    Uri tokenEndpoint,
    bool condition,
    String message) {
  if (condition) return;
  throw new FormatException('Invalid OAuth response for "$tokenEndpoint": '
      '$message.\n\n${response.body}');
}
