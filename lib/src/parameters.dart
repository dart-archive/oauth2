import 'dart:convert';
import 'package:collection/collection.dart';
import 'package:http_parser/http_parser.dart';

typedef Map<String, dynamic> GetParameters(String contentType, String body);

void validate(bool condition, String message) {
  if (condition) return;
  throw new FormatException(message);
}

/// Parses parameters from a response with a JSON body.
Map<String, dynamic> parseJsonParameters(
    String contentTypeString, String body) {

  var contentType =
      contentTypeString == null ? null : new MediaType.parse(contentTypeString);

  // The spec requires a content-type of application/json, but some endpoints
  // (e.g. Dropbox) serve it as text/javascript instead.
  validate(
      contentType != null &&
          (contentType.mimeType == "application/json" ||
              contentType.mimeType == "text/javascript"),
      'content-type was "$contentType", expected "application/json"');

  Map<String, dynamic> parameters;

  var untypedParameters = JSON.decode(body);
  validate(untypedParameters is Map,
      'parameters must be a map, was "$parameters"');
  return DelegatingMap.typed(untypedParameters);
}
