import 'dart:convert';
import 'package:collection/collection.dart';
import 'package:http_parser/http_parser.dart';

typedef Map<String, dynamic> GetParameters(MediaType contentType, String body);

/// Parses parameters from a response with a JSON body.
Map<String, dynamic> parseJsonParameters(MediaType contentType, String body) {
  // The spec requires a content-type of application/json, but some endpoints
  // (e.g. Dropbox) serve it as text/javascript instead.
  if (contentType == null ||
      (contentType.mimeType != "application/json" &&
          contentType.mimeType != "text/javascript")) {
    throw new FormatException(
        'content-type was "$contentType", expected "application/json"');
  }

  Map<String, dynamic> parameters;

  var untypedParameters = JSON.decode(body);

  if (untypedParameters is! Map)
    throw new FormatException('parameters must be a map, was "$parameters"');

  return DelegatingMap.typed(untypedParameters);
}
