// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

@TestOn('vm')
import 'dart:convert';
import 'dart:async';

import 'package:http/http.dart' as http;
import 'package:oauth2/oauth2.dart' as oauth2;
import 'package:test/test.dart';

import 'utils.dart';

final success = jsonEncode({
  'access_token': '2YotnFZFEjr1zCsicMWpAA',
  'token_type': 'bearer',
  'expires_in': 3600,
  'refresh_token': 'tGzv3JOkF0XG5Qx2TlKWIA',
});

var auth = 'Basic Y2xpZW50OnNlY3JldA==';
var authEndpoint = Uri.parse('https://example.com');

void main() {
  var expectClient;
  setUp(() => expectClient = ExpectClient());

  group('basic', () {
    test('builds correct request with client when using basic auth for client',
        () async {
      expectClient.expectRequest((request) async {
        expect(auth, equals(request.headers['authorization']));
        expect(request.bodyFields['grant_type'], equals('password'));
        expect(request.bodyFields['username'], equals('username'));
        expect(request.bodyFields['password'], equals('userpass'));
        return http.Response(success, 200,
            headers: {'content-type': 'application/json'});
      });

      var client = await oauth2.resourceOwnerPasswordGrant(
          authEndpoint, 'username', 'userpass',
          identifier: 'client', secret: 'secret', httpClient: expectClient);

      expect(client.credentials, isNotNull);
      expect(client.credentials.accessToken, equals('2YotnFZFEjr1zCsicMWpAA'));
    });

    test('passes the onCredentialsRefreshed callback to the client', () async {
      expectClient.expectRequest((request) async {
        return http.Response(
            jsonEncode({
              'access_token': '2YotnFZFEjr1zCsicMWpAA',
              'token_type': 'bearer',
              'expires_in': -3600,
              'refresh_token': 'tGzv3JOkF0XG5Qx2TlKWIA',
            }),
            200,
            headers: {'content-type': 'application/json'});
      });

      var isCallbackInvoked = false;

      var client = await oauth2.resourceOwnerPasswordGrant(
          authEndpoint, 'username', 'userpass',
          identifier: 'client', secret: 'secret', httpClient: expectClient,
          onCredentialsRefreshed: (oauth2.Credentials credentials) {
        isCallbackInvoked = true;
      });

      expectClient.expectRequest((request) {
        return Future.value(http.Response(
            jsonEncode(
                {'access_token': 'new access token', 'token_type': 'bearer'}),
            200,
            headers: {'content-type': 'application/json'}));
      });

      expectClient.expectRequest((request) {
        return Future.value(http.Response('good job', 200));
      });

      await client.read(Uri.parse('http://example.com/resource'));
      expect(isCallbackInvoked, equals(true));
    });

    test('builds correct request when using query parameters for client',
        () async {
      expectClient.expectRequest((request) async {
        expect(request.bodyFields['grant_type'], equals('password'));
        expect(request.bodyFields['client_id'], equals('client'));
        expect(request.bodyFields['client_secret'], equals('secret'));
        expect(request.bodyFields['username'], equals('username'));
        expect(request.bodyFields['password'], equals('userpass'));
        return http.Response(success, 200,
            headers: {'content-type': 'application/json'});
      });

      var client = await oauth2.resourceOwnerPasswordGrant(
          authEndpoint, 'username', 'userpass',
          identifier: 'client',
          secret: 'secret',
          basicAuth: false,
          httpClient: expectClient);
      expect(client.credentials, isNotNull);
      expect(client.credentials.accessToken, equals('2YotnFZFEjr1zCsicMWpAA'));
    });

    test('builds correct request using scope', () async {
      expectClient.expectRequest((request) async {
        expect(request.bodyFields['grant_type'], equals('password'));
        expect(request.bodyFields['username'], equals('username'));
        expect(request.bodyFields['password'], equals('userpass'));
        expect(request.bodyFields['scope'], equals('one two'));
        return http.Response(success, 200,
            headers: {'content-type': 'application/json'});
      });

      var client = await oauth2.resourceOwnerPasswordGrant(
          authEndpoint, 'username', 'userpass',
          scopes: ['one', 'two'], httpClient: expectClient);
      expect(client.credentials, isNotNull);
      expect(client.credentials.accessToken, equals('2YotnFZFEjr1zCsicMWpAA'));
    });

    test('builds correct request using scope with custom delimiter', () async {
      expectClient.expectRequest((request) async {
        expect(request.bodyFields['grant_type'], equals('password'));
        expect(request.bodyFields['username'], equals('username'));
        expect(request.bodyFields['password'], equals('userpass'));
        expect(request.bodyFields['scope'], equals('one,two'));
        return http.Response(success, 200,
            headers: {'content-type': 'application/json'});
      });

      await oauth2.resourceOwnerPasswordGrant(
          authEndpoint, 'username', 'userpass',
          scopes: ['one', 'two'], httpClient: expectClient, delimiter: ',');
    });

    test('merges with existing query parameters', () async {
      var authEndpoint = Uri.parse('https://example.com?query=value');

      expectClient.expectRequest((request) async {
        expect(request.bodyFields['grant_type'], equals('password'));
        expect(request.bodyFields['client_id'], equals('client'));
        expect(request.bodyFields['client_secret'], equals('secret'));
        expect(request.bodyFields['username'], equals('username'));
        expect(request.bodyFields['password'], equals('userpass'));
        expect(request.url.queryParameters['query'], equals('value'));
        return http.Response(success, 200,
            headers: {'content-type': 'application/json'});
      });

      var client = await oauth2.resourceOwnerPasswordGrant(
          authEndpoint, 'username', 'userpass',
          identifier: 'client',
          secret: 'secret',
          basicAuth: false,
          httpClient: expectClient);
      expect(client.credentials, isNotNull);
      expect(client.credentials.accessToken, equals('2YotnFZFEjr1zCsicMWpAA'));
    });
  });
}
