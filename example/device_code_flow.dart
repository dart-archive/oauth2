// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:io';

import 'package:oauth2/oauth2.dart' as oauth2;

// These URLs are endpoints that are provided by the authorization
// server. They're usually included in the server's documentation of its
// OAuth2 API.
final deviceEndpoint = Uri.parse('https://oauth2.googleapis.com/device/code');
final tokenEndpoint = Uri.parse('https://oauth2.googleapis.com/token');

// The authorization server will issue each client a separate client
// identifier and secret, which allows the server to tell which client
// is accessing it. Some servers may also have an anonymous
// identifier/secret pair that any client may use.
//
// Note that clients whose source code or binary executable is readily
// available may not be able to make sure the client secret is kept a
// secret. This is fine; OAuth2 servers generally won't rely on knowing
// with certainty that a client is who it claims to be.
final identifier = 'my client identifier';
final secret = 'my client secret';

/// A file in which the users credentials are stored persistently. If the server
/// issues a refresh token allowing the client to refresh outdated credentials,
/// these may be valid indefinitely, meaning the user never has to
/// re-authenticate.
final credentialsFile = File('~/.myapp/credentials.json');

/// Either load an OAuth2 client from saved credentials or authenticate a new
/// one.
Future<oauth2.Client> createClient() async {
  var exists = await credentialsFile.exists();

  // If the OAuth2 credentials have already been saved from a previous run, we
  // just want to reload them.
  if (exists) {
    var credentials =
        oauth2.Credentials.fromJson(await credentialsFile.readAsString());
    return oauth2.Client(credentials, identifier: identifier, secret: secret);
  }

  // If we don't have OAuth2 credentials yet, we need to get the resource owner
  // to authorize us. We're assuming here that we're a command-line application.
  var grant = oauth2.DeviceAuthorizationGrant(
    identifier,
    deviceEndpoint,
    tokenEndpoint,
    secret: secret,
  );

  // A URL on the authorization server (authorizationEndpoint with some additional
  // query parameters). Scopes and state can optionally be passed into this method.
  var device_code = await grant.getDeviceCode(scopes: ['profile']);

  print(
      'open yout browser at ${device_code.verification_uri} and enter the user_code: ${device_code.user_code}');

  // Poll for an accesstoken with an default intervall of 10 seconds if the
  // authorization doesn't returned an interval.
  while (true) {
    try {
      return await grant.pollForToken();
    } catch (e) {
      print(e);
      sleep(Duration(seconds: device_code.interval ?? 10));
    }
  }
}

void main() async {
  var client = await createClient();

  print('successfull authorized');

  // Once you have a Client, you can use it just like any other HTTP client.
  print(await client.read(Uri.http('example.com', 'protected-resources.txt')));

  // Once we're done with the client, save the credentials file. This ensures
  // that if the credentials were automatically refreshed while using the
  // client, the new credentials are available for the next run of the
  // program.
  await credentialsFile.writeAsString(client.credentials.toJson());
}
