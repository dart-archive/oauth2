A client library for authenticating with a remote service via OAuth2 on
behalf of a user, and making authorized HTTP requests with the user's OAuth2
credentials.

OAuth2 allows a client (the program using this library) to access and
manipulate a resource that's owned by a resource owner (the end user) and
lives on a remote server. The client directs the resource owner to an
authorization server (usually but not always the same as the server that
hosts the resource), where the resource owner tells the authorization server
to give the client an access token. This token serves as proof that the
client has permission to access resources on behalf of the resource owner.

OAuth2 provides several different methods for the client to obtain
authorization. At the time of writing, this library only supports the
[AuthorizationCodeGrant][] and [resourceOwnerPasswordGrant][] methods, but
further methods may be added in the future. The following example uses this
method to authenticate, and assumes that the library is being used by a
server-side application.

[AuthorizationCodeGrant]: http://www.dartdocs.org/documentation/oauth2/latest/index.html#oauth2/oauth2.AuthorizationCodeGrant
[resourceOwnerPasswordGrant]: http://www.dartdocs.org/documentation/oauth2/latest/index.html#oauth2/oauth2.resourceOwnerPasswordGrant

## Authorization Code Grant

```dart
import 'dart:io';
import 'package:oauth2/oauth2.dart' as oauth2;

// These URLs are endpoints that are provided by the authorization
// server. They're usually included in the server's documentation of its
// OAuth2 API.
final authorizationEndpoint =
    Uri.parse("http://example.com/oauth2/authorization");
final tokenEndpoint =
    Uri.parse("http://example.com/oauth2/token");

// The authorization server will issue each client a separate client
// identifier and secret, which allows the server to tell which client
// is accessing it. Some servers may also have an anonymous
// identifier/secret pair that any client may use.
//
// Note that clients whose source code or binary executable is readily
// available may not be able to make sure the client secret is kept a
// secret. This is fine; OAuth2 servers generally won't rely on knowing
// with certainty that a client is who it claims to be.
final identifier = "my client identifier";
final secret = "my client secret";

// This is a URL on your application's server. The authorization server
// will redirect the resource owner here once they've authorized the
// client. The redirection will include the authorization code in the
// query parameters.
final redirectUrl = Uri.parse("http://my-site.com/oauth2-redirect");

/// A file in which the users credentials are stored persistently. If the server
/// issues a refresh token allowing the client to refresh outdated credentials,
/// these may be valid indefinitely, meaning the user never has to
/// re-authenticate.
final credentialsFile = new File("~/.myapp/credentials.json");

/// Either load an OAuth2 client from saved credentials or authenticate a new
/// one.
Future<oauth2.Client> getClient() async {
  var exists = await credentialsFile.exists();

  // If the OAuth2 credentials have already been saved from a previous run, we
  // just want to reload them.
  if (exists) {
    var credentials = new oauth2.Credentials.fromJson(
        await credentialsFile.readAsString());
    return new oauth2.Client(credentials,
        identifier: identifier, secret: secret);
  }

  // If we don't have OAuth2 credentials yet, we need to get the resource owner
  // to authorize us. We're assuming here that we're a command-line application.
  var grant = new oauth2.AuthorizationCodeGrant(
      identifier, authorizationEndpoint, tokenEndpoint,
      secret: secret);

  // Redirect the resource owner to the authorization URL. This will be a URL on
  // the authorization server (authorizationEndpoint with some additional query
  // parameters). Once the resource owner has authorized, they'll be redirected
  // to `redirectUrl` with an authorization code.
  //
  // `redirect` is an imaginary function that redirects the resource
  // owner's browser.
  await redirect(grant.getAuthorizationUrl(redirectUrl));
  
  // Another imaginary function that listens for a request to `redirectUrl`.
  var request = await listen(redirectUrl);

  // Once the user is redirected to `redirectUrl`, pass the query parameters to
  // the AuthorizationCodeGrant. It will validate them and extract the
  // authorization code to create a new Client.
  return await grant.handleAuthorizationResponse(request.uri.queryParameters);
}

main() async {
  var client = await getClient();

  // Once you have a Client, you can use it just like any other HTTP client.
  var result = client.read("http://example.com/protected-resources.txt");

  // Once we're done with the client, save the credentials file. This ensures
  // that if the credentials were automatically refreshed while using the
  // client, the new credentials are available for the next run of the
  // program.
  await credentialsFile.writeAsString(client.credentials.toJson());

  print(result);
}
```

## Resource Owner Password Grant

```dart
// This URL is an endpoint that's provided by the authorization server. It's
// usually included in the server's documentation of its OAuth2 API.
final authorizationEndpoint =
    Uri.parse("http://example.com/oauth2/authorization");

// The user should supply their own username and password.
final username = "example user";
final password = "example password";

// The authorization server may issue each client a separate client
// identifier and secret, which allows the server to tell which client
// is accessing it. Some servers may also have an anonymous
// identifier/secret pair that any client may use.
//
// Some servers don't require the client to authenticate itself, in which case
// these should be omitted.
final identifier = "my client identifier";
final secret = "my client secret";

// Make a request to the authorization endpoint that will produce the fully
// authenticated Client.
var client = await oauth2.resourceOwnerPasswordGrant(
    authorizationEndpoint, username, password,
    identifier: identifier, secret: secret);

// Once you have the client, you can use it just like any other HTTP client.
var result = await client.read("http://example.com/protected-resources.txt");

// Once we're done with the client, save the credentials file. This will allow
// us to re-use the credentials and avoid storing the username and password
// directly.
new File("~/.myapp/credentials.json")
    .writeAsString(client.credentials.toJson());
```
