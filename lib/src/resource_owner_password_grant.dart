// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

library resource_owner_password_grant;

import 'dart:async';
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:crypto/crypto.dart';
import 'client.dart';
import 'handle_access_token_response.dart';
import 'utils.dart';

/// Implementation of the [resource owner password grant] (http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-4.3) for oauth 2.
///

/// Returns a fully-authorized [Client] if authorization is successful.
///
/// The client can provide a [clientId] and [clientSecret] for authenticating itself  as required by the server. The
/// default authentication is basic authentication as recommended by the spec. This can be overridden to be passed as
/// query parameters by passing [useBasicAuth]: false.
///
/// Specific scopes can be requested vis [scopes], but is not required.  The server may choose to grant less scopes than
/// actually requested.  The actual scopes granted are returned in [Credentials] property of the [Client].
///
Future<Client> resourceOwnerPasswordGrant(
    Uri authorizationEndpoint, String username, String password,
    {String clientId,
    String clientSecret,
    List<String> scopes: const [],
    bool useBasicAuth: true,
    http.Client httpClient}) async {

  var startTime = new DateTime.now();

  var body = {"grant_type": "password", "username": username, "password": password};

  var headers = {};

  if (clientId != null) {
    if (useBasicAuth) {
      headers['authorization'] = 'Basic ' +
          CryptoUtils.bytesToBase64(UTF8.encode('$clientId:$clientSecret'));
    } else {
      body['client_id'] = clientId;
      if(clientSecret != null) body['client_secret'] = clientSecret;
    }
  }

  if (!scopes.isEmpty) body['scope'] = scopes.join(' ');

  if (httpClient == null) {
    httpClient = new http.Client();
  }

  var response = await httpClient.post(authorizationEndpoint, headers: headers, body: body);

  var credentials = await handleAccessTokenResponse(
      response, authorizationEndpoint, startTime, scopes);
  return new Client(credentials, identifier: clientId, secret: clientSecret);
}
