# 1.0.1

* Support `http_parser` 2.0.0.

# 1.0.0

## Breaking changes

* Requests that use client authentication, such as the
  `AuthorizationCodeGrant`'s access token request and `Credentials`' refresh
  request, now use HTTP Basic authentication by default. This form of
  authentication is strongly recommended by the OAuth 2.0 spec. The new
  `basicAuth` parameter may be set to `false` to force form-based authentication
  for servers that require it.

* `new AuthorizationCodeGrant()` now takes `secret` as an optional named
  argument rather than a required argument. This matches the OAuth 2.0 spec,
  which says that a client secret is only required for confidential clients.

* `new Client()` and `Credentials.refresh()` now take both `identifier` and
  `secret` as optional named arguments rather than required arguments. This
  matches the OAuth 2.0 spec, which says that the server may choose not to
  require client authentication for some flows.

* `new Credentials()` now takes named arguments rather than optional positional
  arguments.

## Non-breaking changes

* Added a `resourceOwnerPasswordGrant` method.

* The `scopes` argument to `AuthorizationCodeGrant.getAuthorizationUrl()` and
  `new Credentials()` and the `newScopes` argument to `Credentials.refresh` now
  take an `Iterable` rather than just a `List`.

* The `scopes` argument to `AuthorizationCodeGrant.getAuthorizationUrl()` now
  defaults to `null` rather than `const []`.

# 0.9.3

* Update the `http` dependency.

* Since `http` 0.11.0 now works in non-`dart:io` contexts, `oauth2` does as
  well.

# 0.9.2

* Expand the dependency on the HTTP package to include 0.10.x.

* Add a README file.
