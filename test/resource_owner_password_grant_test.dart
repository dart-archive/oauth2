// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.
@TestOn("vm")
library resource_owner_password_grant_test;

import 'dart:convert';
import 'dart:io';
import 'package:crypto/crypto.dart';

import 'package:test/test.dart';
import 'package:oauth2/oauth2.dart' as oauth2;

final List<int> ERROR = UTF8.encode(JSON.encode({
  "error": "unauthorized",
  "error_description": "unauthorized",
  "error_uri": "http://error.com"
}));

final List<int> SUCCESS = UTF8.encode(JSON.encode({
  "access_token": "2YotnFZFEjr1zCsicMWpAA",
  "token_type": "bearer",
  "expires_in": 3600,
  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
}));

void main() {
  group('basic', () {
    HttpServer server;
    var authorizationEndpoint =
        Uri.parse('http://${InternetAddress.LOOPBACK_IP_V4.host}:8080');

    setUp(() async {
      server = await HttpServer.bind(InternetAddress.LOOPBACK_IP_V4, 8080);
    });

    test('builds correct request with client when using basic auth for client',
        () async {
      server.take(1).listen((HttpRequest request) {
        request.response.headers.add(
            HttpHeaders.CONTENT_TYPE, 'application/json;charset=UTF-8');
        var auth =
            'Basic ${CryptoUtils.bytesToBase64(UTF8.encode('client:secret'))}';

        expect(auth, equals(request.headers['authorization'].first));
        expect(request.uri.queryParameters['grant_type'], equals('password'));
        expect(request.uri.queryParameters['username'], equals('username'));
        expect(request.uri.queryParameters['password'], equals('userpass'));
        request.response.statusCode = HttpStatus.OK;
        request.response.add(SUCCESS);
        request.response.close();
      });

      var client = await oauth2.resourceOwnerPasswordGrant(
          authorizationEndpoint, 'username', 'userpass',
          clientId: 'client', clientSecret: 'secret');
      expect(client.credentials, isNotNull);
      expect(client.credentials.accessToken, equals('2YotnFZFEjr1zCsicMWpAA'));
    }, timeout: new Timeout(new Duration(seconds: 1)));

    test('builds correct request when using query parameters for client',
        () async {
      server.take(1).listen((HttpRequest request) {
        request.response.headers.add(
            HttpHeaders.CONTENT_TYPE, 'application/json;charset=UTF-8');
        expect(request.uri.queryParameters['grant_type'], equals('password'));
        expect(request.uri.queryParameters['client_id'], equals('client'));
        expect(request.uri.queryParameters['client_secret'], equals('secret'));
        expect(request.uri.queryParameters['username'], equals('username'));
        expect(request.uri.queryParameters['password'], equals('userpass'));
        request.response.statusCode = HttpStatus.OK;
        request.response.add(SUCCESS);
        request.response.close();
      });

      var client = await oauth2.resourceOwnerPasswordGrant(
          authorizationEndpoint, 'username', 'userpass',
          clientId: 'client', clientSecret: 'secret', useBasicAuth: false);
      expect(client.credentials, isNotNull);
      expect(client.credentials.accessToken, equals('2YotnFZFEjr1zCsicMWpAA'));
    }, timeout: new Timeout(new Duration(seconds: 1)));


    test('builds correct request using scope',
        () async {
      server.take(1).listen((HttpRequest request) {
        request.response.headers.add(
            HttpHeaders.CONTENT_TYPE, 'application/json;charset=UTF-8');
        expect(request.uri.queryParameters['grant_type'], equals('password'));
        expect(request.uri.queryParameters['username'], equals('username'));
        expect(request.uri.queryParameters['password'], equals('userpass'));
        expect(request.uri.queryParameters['scope'],equals ('one two'));
        request.response.statusCode = HttpStatus.OK;
        request.response.add(SUCCESS);
        request.response.close();
      });

      var client = await oauth2.resourceOwnerPasswordGrant(
          authorizationEndpoint, 'username', 'userpass', scopes: ['one','two']);
      expect(client.credentials, isNotNull);
      expect(client.credentials.accessToken, equals('2YotnFZFEjr1zCsicMWpAA'));

    }, timeout: new Timeout(new Duration(seconds: 1)));

    tearDown(() {
      server.close();
    });
  });
}
