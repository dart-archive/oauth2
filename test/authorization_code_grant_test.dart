// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:convert';

import 'package:test/test.dart';
import 'package:http/http.dart' as http;
import 'package:oauth2/oauth2.dart' as oauth2;

import 'utils.dart';

final redirectUrl = Uri.parse('http://example.com/redirect');

void main() {
  ExpectClient client;
  oauth2.AuthorizationCodeGrant grant;
  setUp(() {
    client = ExpectClient();
    grant = oauth2.AuthorizationCodeGrant(
        'identifier',
        Uri.parse('https://example.com/authorization'),
        Uri.parse('https://example.com/token'),
        secret: 'secret',
        httpClient: client);
  });

  group('.getAuthorizationUrl', () {
    test('builds the correct URL', () {
      expect(
          grant.getAuthorizationUrl(redirectUrl).toString(),
          allOf([
            startsWith('https://example.com/authorization?response_type=code'),
            contains('&client_id=identifier'),
            contains('&redirect_uri=http%3A%2F%2Fexample.com%2Fredirect'),
            matches(r'&code_challenge=[A-Za-z0-9\+\/\-\_]{43}'),
            contains('&code_challenge_method=S256')
          ]));
    });

    test('builds the correct URL with scopes', () {
      var authorizationUrl = grant
          .getAuthorizationUrl(redirectUrl, scopes: ['scope', 'other/scope']);
      expect(
          authorizationUrl.toString(),
          allOf([
            startsWith('https://example.com/authorization?response_type=code'),
            contains('&client_id=identifier'),
            contains('&redirect_uri=http%3A%2F%2Fexample.com%2Fredirect'),
            matches(r'&code_challenge=[A-Za-z0-9\+\/\-\_]{43}'),
            contains('&code_challenge_method=S256'),
            contains('&scope=scope+other%2Fscope')
          ]));
    });

    test('separates scopes with the correct delimiter', () {
      var grant = oauth2.AuthorizationCodeGrant(
          'identifier',
          Uri.parse('https://example.com/authorization'),
          Uri.parse('https://example.com/token'),
          secret: 'secret',
          httpClient: client,
          delimiter: '_');
      var authorizationUrl = grant
          .getAuthorizationUrl(redirectUrl, scopes: ['scope', 'other/scope']);
      expect(
          authorizationUrl.toString(),
          allOf([
            startsWith('https://example.com/authorization?response_type=code'),
            contains('&client_id=identifier'),
            contains('&redirect_uri=http%3A%2F%2Fexample.com%2Fredirect'),
            matches(r'&code_challenge=[A-Za-z0-9\+\/\-\_]{43}'),
            contains('&code_challenge_method=S256'),
            contains('&scope=scope_other%2Fscope')
          ]));
    });

    test('builds the correct URL with state', () {
      var authorizationUrl =
          grant.getAuthorizationUrl(redirectUrl, state: 'state');
      expect(
          authorizationUrl.toString(),
          allOf([
            startsWith('https://example.com/authorization?response_type=code'),
            contains('&client_id=identifier'),
            contains('&redirect_uri=http%3A%2F%2Fexample.com%2Fredirect'),
            matches(r'&code_challenge=[A-Za-z0-9\+\/\-\_]{43}'),
            contains('&code_challenge_method=S256'),
            contains('&state=state')
          ]));
    });

    test('merges with existing query parameters', () {
      grant = oauth2.AuthorizationCodeGrant(
          'identifier',
          Uri.parse('https://example.com/authorization?query=value'),
          Uri.parse('https://example.com/token'),
          secret: 'secret',
          httpClient: client);

      var authorizationUrl = grant.getAuthorizationUrl(redirectUrl);
      expect(
          authorizationUrl.toString(),
          allOf([
            startsWith('https://example.com/authorization?query=value'),
            contains('&response_type=code'),
            contains('&client_id=identifier'),
            contains('&redirect_uri=http%3A%2F%2Fexample.com%2Fredirect'),
            matches(r'&code_challenge=[A-Za-z0-9\+\/\-\_]{43}'),
            contains('&code_challenge_method=S256'),
          ]));
    });

    test("can't be called twice", () {
      grant.getAuthorizationUrl(redirectUrl);
      expect(() => grant.getAuthorizationUrl(redirectUrl), throwsStateError);
    });
  });

  group('.handleAuthorizationResponse', () {
    test("can't be called before .getAuthorizationUrl", () {
      expect(grant.handleAuthorizationResponse({}), throwsStateError);
    });

    test("can't be called twice", () {
      grant.getAuthorizationUrl(redirectUrl);
      expect(grant.handleAuthorizationResponse({'code': 'auth code'}),
          throwsFormatException);
      expect(grant.handleAuthorizationResponse({'code': 'auth code'}),
          throwsStateError);
    });

    test('must have a state parameter if the authorization URL did', () {
      grant.getAuthorizationUrl(redirectUrl, state: 'state');
      expect(grant.handleAuthorizationResponse({'code': 'auth code'}),
          throwsFormatException);
    });

    test('must have the same state parameter the authorization URL did', () {
      grant.getAuthorizationUrl(redirectUrl, state: 'state');
      expect(
          grant.handleAuthorizationResponse(
              {'code': 'auth code', 'state': 'other state'}),
          throwsFormatException);
    });

    test('must have a code parameter', () {
      grant.getAuthorizationUrl(redirectUrl);
      expect(grant.handleAuthorizationResponse({}), throwsFormatException);
    });

    test('with an error parameter throws an AuthorizationException', () {
      grant.getAuthorizationUrl(redirectUrl);
      expect(grant.handleAuthorizationResponse({'error': 'invalid_request'}),
          throwsA((e) => e is oauth2.AuthorizationException));
    });

    test('sends an authorization code request', () {
      grant.getAuthorizationUrl(redirectUrl);
      client.expectRequest((request) {
        expect(request.method, equals('POST'));
        expect(request.url.toString(), equals(grant.tokenEndpoint.toString()));
        expect(
            request.bodyFields,
            allOf([
              containsPair('grant_type', 'authorization_code'),
              containsPair('code', 'auth code'),
              containsPair('redirect_uri', redirectUrl.toString()),
              containsPair(
                  'code_verifier', matches(r'[A-Za-z0-9\-\.\_\~]{128}'))
            ]));
        expect(request.headers,
            containsPair('Authorization', 'Basic aWRlbnRpZmllcjpzZWNyZXQ='));

        return Future.value(http.Response(
            jsonEncode({
              'access_token': 'access token',
              'token_type': 'bearer',
            }),
            200,
            headers: {'content-type': 'application/json'}));
      });

      expect(
          grant.handleAuthorizationResponse({'code': 'auth code'}).then(
              (client) => client.credentials.accessToken),
          completion(equals('access token')));
    });
  });

  group('.handleAuthorizationCode', () {
    test("can't be called before .getAuthorizationUrl", () {
      expect(grant.handleAuthorizationCode('auth code'), throwsStateError);
    });

    test("can't be called twice", () {
      grant.getAuthorizationUrl(redirectUrl);
      expect(grant.handleAuthorizationCode('auth code'), throwsFormatException);
      expect(grant.handleAuthorizationCode('auth code'), throwsStateError);
    });

    test('sends an authorization code request', () {
      grant.getAuthorizationUrl(redirectUrl);
      client.expectRequest((request) {
        expect(request.method, equals('POST'));
        expect(request.url.toString(), equals(grant.tokenEndpoint.toString()));
        expect(
            request.bodyFields,
            allOf([
              containsPair('grant_type', 'authorization_code'),
              containsPair('code', 'auth code'),
              containsPair('redirect_uri', redirectUrl.toString()),
              containsPair(
                  'code_verifier', matches(r'[A-Za-z0-9\-\.\_\~]{128}'))
            ]));
        expect(request.headers,
            containsPair('Authorization', 'Basic aWRlbnRpZmllcjpzZWNyZXQ='));

        return Future.value(http.Response(
            jsonEncode({
              'access_token': 'access token',
              'token_type': 'bearer',
            }),
            200,
            headers: {'content-type': 'application/json'}));
      });

      expect(grant.handleAuthorizationCode('auth code'),
          completion(predicate((client) {
        expect(client.credentials.accessToken, equals('access token'));
        return true;
      })));
    });
  });

  group('with basicAuth: false', () {
    setUp(() {
      client = ExpectClient();
      grant = oauth2.AuthorizationCodeGrant(
          'identifier',
          Uri.parse('https://example.com/authorization'),
          Uri.parse('https://example.com/token'),
          secret: 'secret',
          basicAuth: false,
          httpClient: client);
    });

    test('.handleAuthorizationResponse sends an authorization code request',
        () {
      grant.getAuthorizationUrl(redirectUrl);
      client.expectRequest((request) {
        expect(request.method, equals('POST'));
        expect(request.url.toString(), equals(grant.tokenEndpoint.toString()));
        expect(
            request.bodyFields,
            allOf([
              containsPair('grant_type', 'authorization_code'),
              containsPair('code', 'auth code'),
              containsPair('redirect_uri', redirectUrl.toString()),
              containsPair(
                  'code_verifier', matches(r'[A-Za-z0-9\-\.\_\~]{128}')),
              containsPair('client_id', 'identifier'),
              containsPair('client_secret', 'secret')
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
          grant.handleAuthorizationResponse({'code': 'auth code'}).then(
              (client) => client.credentials.accessToken),
          completion(equals('access token')));
    });

    test('.handleAuthorizationCode sends an authorization code request', () {
      grant.getAuthorizationUrl(redirectUrl);
      client.expectRequest((request) {
        expect(request.method, equals('POST'));
        expect(request.url.toString(), equals(grant.tokenEndpoint.toString()));
        expect(
            request.bodyFields,
            allOf([
              containsPair('grant_type', 'authorization_code'),
              containsPair('code', 'auth code'),
              containsPair('redirect_uri', redirectUrl.toString()),
              containsPair(
                  'code_verifier', matches(r'[A-Za-z0-9\-\.\_\~]{128}')),
              containsPair('client_id', 'identifier'),
              containsPair('client_secret', 'secret')
            ]));

        return Future.value(http.Response(
            jsonEncode({
              'access_token': 'access token',
              'token_type': 'bearer',
            }),
            200,
            headers: {'content-type': 'application/json'}));
      });

      expect(grant.handleAuthorizationCode('auth code'),
          completion(predicate((client) {
        expect(client.credentials.accessToken, equals('access token'));
        return true;
      })));
    });
  });

  group('onCredentialsRefreshed', () {
    test('is correctly propagated', () async {
      var isCallbackInvoked = false;
      var grant = oauth2.AuthorizationCodeGrant(
          'identifier',
          Uri.parse('https://example.com/authorization'),
          Uri.parse('https://example.com/token'),
          secret: 'secret',
          basicAuth: false,
          httpClient: client, onCredentialsRefreshed: (credentials) {
        isCallbackInvoked = true;
      });

      grant.getAuthorizationUrl(redirectUrl);
      client.expectRequest((request) {
        return Future.value(http.Response(
            jsonEncode({
              'access_token': 'access token',
              'token_type': 'bearer',
              'expires_in': -3600,
              'refresh_token': 'refresh token',
            }),
            200,
            headers: {'content-type': 'application/json'}));
      });

      var oauth2Client = await grant.handleAuthorizationCode('auth code');

      client.expectRequest((request) {
        return Future.value(http.Response(
            jsonEncode(
                {'access_token': 'new access token', 'token_type': 'bearer'}),
            200,
            headers: {'content-type': 'application/json'}));
      });

      client.expectRequest((request) {
        return Future.value(http.Response('good job', 200));
      });

      await oauth2Client.read(Uri.parse('http://example.com/resource'));

      expect(isCallbackInvoked, equals(true));
    });
  });
}
