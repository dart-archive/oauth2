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

/// Implementation of the [resource owner password grant] for oauth 2.
///
/// [resource owner password grant]: http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-4.1

/// Returns a fully-authorized [Client] if authorization is successful.
///
/// The client can provide a [clientId] and [clientSecret] for confidential access as required by the server either
/// by basic authentication (default and recommended by the spec) or as additional query parameters [useBasicAuth]: false.
///
/// Specific scopes can be requests vis [scopes], but is not required.  The server may choose to grant less scopes than
/// actually requested.  The actual scopes granted are returned in [Client.credentials.scopes].
///
Future<Client> resourceOwnerPasswordGrant(
    Uri authorizationEndpoint, String username, String password,
    {String clientId, String clientSecret: '', List<String> scopes: const [],
    bool useBasicAuth: true, http.Client httpClient}) async {

  var startTime = new DateTime.now();
  var parameters = {"grant_type": "password"};
  var headers = {};

  if(clientId != null){
    if(useBasicAuth){
      headers['authorization'] = 'Basic ' +
      CryptoUtils.bytesToBase64(UTF8.encode('$clientId:$clientSecret'));
    }else {
      parameters['client_id'] = clientId;
      parameters['client_secret'] = clientSecret;
    }
  }

  parameters["username"] = username;
  parameters["password"] = password;

  if (!scopes.isEmpty) parameters['scope'] = scopes.join(' ');

  var url = addQueryParameters(authorizationEndpoint, parameters);

  if (httpClient == null) {
    httpClient = new http.Client();
  }

  var response = await httpClient.post(url, headers: headers);

  var credentials = await handleAccessTokenResponse(
      response, authorizationEndpoint, startTime, scopes);
  return new Client(clientId, clientSecret, credentials);
}
