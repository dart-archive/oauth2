import 'dart:convert';
import 'package:collection/collection.dart';
import 'package:http_parser/http_parser.dart';

typedef Map<String, dynamic> GetParameters(String contentType, String body, Uri tokenEndpoint);

void validate(bool condition, String message) {
  if (condition) return;
  throw new FormatException(message);
}

/// Parses parameters from a response with either a JSON or URL-encoded body.
Map<String, dynamic> parseJsonOrUrlEncodedParameters(
    String contentTypeString, String body, Uri tokenEndpoint) {

  var contentType =
      contentTypeString == null ? null : new MediaType.parse(contentTypeString);

  try {
    // The spec requires a content-type of application/json, but some endpoints
    // (e.g. Dropbox) serve it as text/javascript instead.
    validate(
        contentType != null &&
            (contentType.mimeType == "application/json" ||
                contentType.mimeType == "text/javascript" ||
                contentType.mimeType == "application/x-www-form-urlencoded"),
        'content-type was "$contentType", expected "application/json" or "application/x-www-form-urlencoded"');
  } on FormatException catch(e) {
    throw new FormatException('Invalid OAuth response for "$tokenEndpoint": '
        '${e.message}.\n\n$body');
  }

  Map<String, dynamic> parameters;

  if (contentType.mimeType == "application/x-www-form-urlencoded") {
    parameters = {};

    for (var unit in body.split('&')) {
      var separator = unit.lastIndexOf('=');

      // The '=' can't be the first or last character in a URL-encoded string
      //
      // For example, in 'a=b', the lowest index it can have is 1, and the greatest is
      // `unit.length - 2`.
      if (separator > 0 && separator < unit.length - 1) {
        var key = unit.substring(0, separator);
        var value = Uri.decodeComponent(unit.substring(separator + 1));
        parameters[key] = value;
      }
    }
  } else {
    try {
      var untypedParameters = JSON.decode(body);
      validate(untypedParameters is Map,
          'parameters must be a map, was "$parameters"');
      parameters = DelegatingMap.typed(untypedParameters);
    } on FormatException catch(e) {
      throw new FormatException('Invalid OAuth response for "$tokenEndpoint": '
          '${e.message}.\n\n$body');
    }
  }

  return parameters;
}
