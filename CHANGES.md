## Changes

* v3.0.0
    * Update ldapauth-fork to v5 which upgrade ldapjs to v2
* v2.1.4
    * Allow any version of @types/node
* v2.1.3
    * [#86](https://github.com/vesse/passport-ldapauth/pull/86) Allow configuring missing credentials response status.
* v2.1.2
    * [#80](https://github.com/vesse/passport-ldapauth/pull/80) Run error handler only once since the a new LdapAuth instance is created for every authenticate request.
* v2.1.1
    * Bump deps
* v2.1.0
    * [#77](https://github.com/vesse/passport-ldapauth/pull/77) Add `noSuchObject` error message
* v2.0.0
    * `ldapauth-fork` major version update now uses Bunyan logger
    * Added TypeScript type definitions
* v1.0.0
    * `ldapauth-fork` is now an event emitter. Emitted errors will cause authentication error.
    * [#38](https://github.com/vesse/passport-ldapauth/pull/38) Added option to handle erros as failures with `handleErrorsAsFailures`. Additionally a *synchronous* `failureErrorCallback` function that receives the error as argument can be provided.
* v0.6.0
    * Added option `credentialsLookup` that can be used eg. to add Basic Auth header parsing support.
* v0.5.0
    * Updated deps. ldapauth-fork update changes bind credentials handling to work better with falsy values needed in anonymous bind.
* v0.4.0
    * Updated ldapauth-fork which updates ldapjs to 1.0.0
* v0.3.1
    * [#35](https://github.com/vesse/passport-ldapauth/issues/35) - Show more specific error messages from Microsoft AD login errors if identified.
* v0.3.0
    * [#10](https://github.com/vesse/passport-ldapauth/issues/10) - Add support for fetching groups. While this is really coming from [ldapauth-fork](https://github.com/vesse/node-ldapauth-fork), updated the minor version of this library as well to draw attention to new features.
* v0.2.6
    * [#24](https://github.com/vesse/passport-ldapauth/pull/24) - Pass `req` to options function, enables request specific LDAP configuration.
* v0.2.5
    * [#21](https://github.com/vesse/passport-ldapauth/issues/21) - Handle `constraintViolationError` as a login failure instead of an error.
* v0.2.4
    * Inherit from [passport-strategy](https://github.com/jaredhanson/passport-strategy) like `passport-local` and others do.
* v0.2.3
    * Documentation using the same keys as ldapjs (bindDn and bindCredentials)
* v0.2.2
    * Allow configuring flash messages when calling `passport.authenticate()`
    * Return HTTP 400 when username or password is missing
* v0.2.1
    * Passport as peerDependency, prevents version incompatibility
* v0.2.0
    * [#8](https://github.com/vesse/passport-ldapauth/issues/8) - Possibility to provide a callback function instead of options object to constructor (contributed by Linagora)
    * Update Passport dependency to 0.2.0
    * Get rid of `var self = this;`
* v0.1.2
    * [#6](https://github.com/vesse/passport-ldapauth/issues/6) - Handle NoSuchObjectError as login failure.
* v0.1.1
    * Documentation changes due to renaming git repository of `ldapauth-fork`
* v0.1.0
    * Use [ldapauth-fork](https://github.com/vesse/node-ldapauth-fork) instead of
      [ldapauth](https://github.com/trentm/node-ldapauth)
        * ldapjs upgraded to 0.6.3
        * New options including `tlsOptions`
    * Refactored tests
* v0.0.6 (14 July 2013)
    * Fixes [#1](https://github.com/vesse/passport-ldapauth/issues/1)
    * Updated devDependencies
* v0.0.5 (16 April 2013)
    * Create LDAP client on every request to prevent socket being closed due
      to inactivity.
* v0.0.4 (14 April 2013)
    * Fixed passport-ldapauth version range.
* v0.0.3 (14 April 2013)
    * Initial release.
