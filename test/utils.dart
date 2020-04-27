// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:collection' show Queue;

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:oauth2/oauth2.dart' as oauth2;
import 'package:test/test.dart';

class ExpectClient extends MockClient {
  final Queue<MockClientHandler> _handlers;

  ExpectClient._(MockClientHandler fn)
      : _handlers = Queue<MockClientHandler>(),
        super(fn);

  factory ExpectClient() {
    var client;
    client = ExpectClient._((request) => client._handleRequest(request));
    return client;
  }

  void expectRequest(MockClientHandler fn) {
    var completer = Completer();
    expect(completer.future, completes);

    _handlers.add((request) {
      completer.complete(null);
      return fn(request);
    });
  }

  Future<http.Response> _handleRequest(http.Request request) {
    if (_handlers.isEmpty) {
      return Future.value(http.Response('not found', 404));
    } else {
      return _handlers.removeFirst()(request);
    }
  }
}

/// A matcher for functions that throw AuthorizationException.
final Matcher throwsAuthorizationException =
    throwsA(const TypeMatcher<oauth2.AuthorizationException>());

/// A matcher for functions that throw ExpirationException.
final Matcher throwsExpirationException =
    throwsA(const TypeMatcher<oauth2.ExpirationException>());
