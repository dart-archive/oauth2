// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.
@TestOn("vm")
library resource_owner_password_grant_test;

import 'dart:convert';
import 'dart:async';
import 'package:http/http.dart' as http;
import 'package:crypto/crypto.dart';

import 'package:test/test.dart';
import 'package:oauth2/oauth2.dart' as oauth2;
import 'utils.dart';

final String SUCCESS = JSON.encode({
  "access_token": "2YotnFZFEjr1zCsicMWpAA",
  "token_type": "bearer",
  "expires_in": 3600,
  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
});

var auth = 'Basic ${CryptoUtils.bytesToBase64(UTF8.encode('client:secret'))}';
var authEndpoint = Uri.parse('https://example.com');
var expectClient = new ExpectClient();

void main() {
  group('basic', () {
    test('builds correct request with client when using basic auth for client',
        () async {
      expectClient.expectRequest((request) {
        expect(auth, equals(request.headers['authorization']));
        expect(request.bodyFields['grant_type'], equals('password'));
        expect(request.bodyFields['username'], equals('username'));
        expect(request.bodyFields['password'], equals('userpass'));
        return new Future.value(new http.Response(SUCCESS, 200,
            headers: {'content-type': 'application/json'}));
      });

      var client = await oauth2.resourceOwnerPasswordGrant(
          authEndpoint, 'username', 'userpass',
          clientId: 'client', clientSecret: 'secret', httpClient: expectClient);

      expect(client.credentials, isNotNull);
      expect(client.credentials.accessToken, equals('2YotnFZFEjr1zCsicMWpAA'));
    });

    test('builds correct request when using query parameters for client',
        () async {
      expectClient.expectRequest((request) {
        expect(request.bodyFields['grant_type'], equals('password'));
        expect(request.bodyFields['client_id'], equals('client'));
        expect(request.bodyFields['client_secret'], equals('secret'));
        expect(request.bodyFields['username'], equals('username'));
        expect(request.bodyFields['password'], equals('userpass'));
        return new Future.value(new http.Response(SUCCESS, 200,
            headers: {'content-type': 'application/json'}));
      });

      var client = await oauth2.resourceOwnerPasswordGrant(
          authEndpoint, 'username', 'userpass',
          clientId: 'client',
          clientSecret: 'secret',
          useBasicAuth: false,
          httpClient: expectClient);
      expect(client.credentials, isNotNull);
      expect(client.credentials.accessToken, equals('2YotnFZFEjr1zCsicMWpAA'));
    });

    test('builds correct request using scope', () async {
      expectClient.expectRequest((request) {
        expect(request.bodyFields['grant_type'], equals('password'));
        expect(request.bodyFields['username'], equals('username'));
        expect(request.bodyFields['password'], equals('userpass'));
        expect(request.bodyFields['scope'], equals('one two'));
        return new Future.value(new http.Response(SUCCESS, 200,
            headers: {'content-type': 'application/json'}));
      });

      var client = await oauth2.resourceOwnerPasswordGrant(
          authEndpoint, 'username', 'userpass',
          scopes: ['one', 'two'], httpClient: expectClient);
      expect(client.credentials, isNotNull);
      expect(client.credentials.accessToken, equals('2YotnFZFEjr1zCsicMWpAA'));
    });

    test('merges with existing query parameters', () async {
      var authEndpoint = Uri.parse('https://example.com?query=value');

      expectClient.expectRequest((request) {
        expect(request.bodyFields['grant_type'], equals('password'));
        expect(request.bodyFields['client_id'], equals('client'));
        expect(request.bodyFields['client_secret'], equals('secret'));
        expect(request.bodyFields['username'], equals('username'));
        expect(request.bodyFields['password'], equals('userpass'));
        expect(request.url.queryParameters['query'], equals('value'));
        return new Future.value(new http.Response(SUCCESS, 200,
            headers: {'content-type': 'application/json'}));
      });

      var client = await oauth2.resourceOwnerPasswordGrant(
          authEndpoint, 'username', 'userpass',
          clientId: 'client',
          clientSecret: 'secret',
          useBasicAuth: false,
          httpClient: expectClient);
      expect(client.credentials, isNotNull);
      expect(client.credentials.accessToken, equals('2YotnFZFEjr1zCsicMWpAA'));
    });
  });
}
