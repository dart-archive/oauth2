// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:oauth2/oauth2.dart' as oauth2;
import 'package:oauth2/oauth2.dart';
import 'package:test/test.dart';

import 'utils.dart';

void main() {
  late ExpectClient client;
  late oauth2.DeviceAuthorizationGrant grant;

  setUp(() {
    client = ExpectClient();
    grant = oauth2.DeviceAuthorizationGrant(
        'identifier',
        Uri.parse('https://example.com/device/code'),
        Uri.parse('https://example.com/token'),
        secret: 'secret',
        basicAuth: false,
        httpClient: client);
  });

  group('.getDeviceCode', () {
    test('sends an code request', () async {
      client.expectRequest((request) {
        expect(request.method, equals('POST'));
        expect(request.url.toString(), equals(grant.deviceEndpoint.toString()));
        expect(
            request.bodyFields,
            allOf([
              containsPair('client_id', 'identifier'),
              containsPair('scope', 'test_scope')
            ]));

        return Future.value(http.Response(
            jsonEncode({
              'device_code': 'deviceCode',
              'user_code': 'userCode',
              'verification_uri': 'https://examle.com/verify',
              'expires_in': 1234,
            }),
            200,
            headers: {'content-type': 'application/json'}));
      });

      expect(
          await grant.getDeviceCode(scopes: ['test_scope']),
          isA<DeviceProperties>()
              .having((c) => c.device_code, 'device_code', 'deviceCode'));
    });

    test("can't be called twice", () async {
      client.expectRequest((request) => Future.value(http.Response(
          jsonEncode({
            'device_code': 'deviceCode',
            'user_code': 'userCode',
            'verification_uri': 'https://examle.com/verify',
            'expires_in': 1234,
          }),
          200,
          headers: {'content-type': 'application/json'})));
      await grant.getDeviceCode();
      expect(() async => await grant.getDeviceCode(), throwsStateError);
    });
  });

  group('.pollForToken', () {
    test('sends an access token request', () async {
      client.expectRequest((request) => Future.value(http.Response(
          jsonEncode({
            'device_code': 'deviceCode',
            'user_code': 'userCode',
            'verification_uri': 'https://examle.com/verify',
            'expires_in': 1234,
          }),
          200,
          headers: {'content-type': 'application/json'})));
      await grant.getDeviceCode();

      client.expectRequest((request) {
        expect(request.method, equals('POST'));
        expect(request.url.toString(), equals(grant.tokenEndpoint.toString()));

        expect(
            request.bodyFields,
            allOf([
              containsPair('client_id', 'identifier'),
              containsPair('device_code', 'deviceCode'),
              containsPair(
                  'grant_type', 'urn:ietf:params:oauth:grant-type:device_code'),
            ]));

        return Future.value(http.Response(
            jsonEncode({
              'access_token': 'access token',
              'token_type': 'bearer',
            }),
            200,
            headers: {'content-type': 'application/json'}));
      });

      expect(
          await grant.pollForToken(),
          isA<oauth2.Client>().having((c) => c.credentials.accessToken,
              'credentials.accessToken', 'access token'));
    });

    test("can't be called twice, after success", () async {
      client.expectRequest((request) => Future.value(http.Response(
          jsonEncode({
            'device_code': 'deviceCode',
            'user_code': 'userCode',
            'verification_uri': 'https://examle.com/verify',
            'expires_in': 1234,
          }),
          200,
          headers: {'content-type': 'application/json'})));
      await grant.getDeviceCode();

      client.expectRequest((request) => Future.value(http.Response(
          jsonEncode({
            'access_token': 'access token',
            'token_type': 'bearer',
          }),
          200,
          headers: {'content-type': 'application/json'})));
      await grant.pollForToken();
      expect(grant.pollForToken(), throwsStateError);
    });

    test("can't be called before .getDeviceCode", () async {
      expect(grant.pollForToken(), throwsStateError);
    });
  });
}
