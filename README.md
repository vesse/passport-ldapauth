# passport-ldapauth

[![Build Status](https://travis-ci.org/vesse/passport-ldapauth.svg)](https://travis-ci.org/vesse/passport-ldapauth)
[![npm](https://img.shields.io/npm/dm/passport-ldapauth.svg)](http://npmjs.com/package/passport-ldapauth)
[![Sponsored by Wakeone](https://img.shields.io/badge/sponsored%20by-wakeone-389fc1.svg)](https://wakeone.co)

[Passport](http://passportjs.org/) authentication strategy against LDAP / AD server. This module is a Passport strategy wrapper for [ldapauth-fork](https://github.com/vesse/node-ldapauth-fork).

This module lets you authenticate using LDAP or AD in your Node.js applications. By plugging into Passport, LDAP authentication can be integrated into any framework that supports Connect-style middleware.

## Install

```
npm install passport-ldapauth
```

## Usage
### Configure strategy

```javascript
var LdapStrategy = require('passport-ldapauth');

passport.use(new LdapStrategy({
    server: {
      url: 'ldap://localhost:389',
      ...
    }
  }));
```

* `server`: LDAP settings. These are passed directly to [ldapauth-fork](https://github.com/vesse/node-ldapauth-fork). See its documentation for all available options.
    * `url`: e.g. `ldap://localhost:389`
    * `bindDN`: e.g. `cn='root'`
    * `bindCredentials`: Password for bindDN
    * `searchBase`: e.g. `o=users,o=example.com`
    * `searchFilter`:  LDAP search filter, e.g. `(uid={{username}})`. Use literal `{{username}}` to have the given username used in the search.
    * `searchAttributes`: Optional array of attributes to fetch from LDAP server, e.g. `['displayName', 'mail']`. Defaults to `undefined`, i.e. fetch all attributes
    * `tlsOptions`: Optional object with options accepted by Node.js [tls](http://nodejs.org/api/tls.html#tls_tls_connect_options_callback) module.
* `usernameField`: Field name where the username is found, defaults to _username_
* `passwordField`: Field name where the password is found, defaults to _password_
* `credentialsLookup`: Optional, synchronous function that provides the login credentials from `req`. See [below](#credentialslookup) for more.
* `missingCredentialsStatus`: Returned HTTP status code when credentials could not be found in the request. Defaults to _400_
* `handleErrorsAsFailures`: When `true`, unknown errors and ldapjs emitted errors are handled as authentication failures instead of errors (default: `false`).
* `failureErrorCallback`: Optional, synchronous function that is called with the received error when `handleErrorsAsFailures` is enabled.
* `passReqToCallback`: When `true`, `req` is the first argument to the verify callback (default: `false`):

        passport.use(new LdapStrategy(..., function(req, user, done) {
            ...
            done(null, user);
          }
        ));

Note: you can pass a function instead of an object as `options`, see the [example below](#asynchronous-configuration-retrieval)

### Authenticate requests

Use `passport.authenticate()`, specifying the `'ldapauth'` strategy, to authenticate requests.

#### `authenticate()` options

In addition to [default authentication options](http://passportjs.org/guide/authenticate/) the following flash message options are available for `passport.authenticate()`:

 * `badRequestMessage`: missing username/password (default: 'Missing credentials')
 * `invalidCredentials`: `InvalidCredentialsError` and `/no such user/i` LDAP errors (default: 'Invalid username/password')
 * `noSuchObject`: `NoSuchObjectError` LDAP errors (default: 'Bad search base')
 * `userNotFound`: LDAP returns no error but also no user (default: 'Invalid username/password')
 * `constraintViolation`: user account is locked (default: 'Exceeded password retry limit, account locked')

And for [Microsoft AD messages](http://www-01.ibm.com/support/docview.wss?uid=swg21290631), these flash message options can also be used (used instead of `invalidCredentials` if matching error code is found):

 * `invalidLogonHours`: not being allowed to login at this current time (default: 'Not Permitted to login at this time')
 * `invalidWorkstation`: not being allowed to login from this current location (default: 'Not permited to logon at this workstation')
 * `passwordExpired`: expired password (default: 'Password expired')
 * `accountDisabled`: disabled account (default: 'Account disabled')
 * `accountExpired`: expired account (default: 'Account expired')
 * `passwordMustChange`: password change (default: 'User must reset password')
 * `accountLockedOut`: locked out account (default: 'User account locked')

## Express example

```javascript
var express      = require('express'),
    passport     = require('passport'),
    bodyParser   = require('body-parser'),
    LdapStrategy = require('passport-ldapauth');

var OPTS = {
  server: {
    url: 'ldap://localhost:389',
    bindDN: 'cn=root',
    bindCredentials: 'secret',
    searchBase: 'ou=passport-ldapauth',
    searchFilter: '(uid={{username}})'
  }
};

var app = express();

passport.use(new LdapStrategy(OPTS));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.use(passport.initialize());

app.post('/login', passport.authenticate('ldapauth', {session: false}), function(req, res) {
  res.send({status: 'ok'});
});

app.listen(8080);
```

### Active Directory over SSL example

Simple example config for connecting over `ldaps://` to a server requiring some internal CA certificate (often the case in corporations using Windows AD).

```javascript
var fs = require('fs');

var opts = {
  server: {
    url: 'ldaps://ad.corporate.com:636',
    bindDN: 'cn=non-person,ou=system,dc=corp,dc=corporate,dc=com',
    bindCredentials: 'secret',
    searchBase: 'dc=corp,dc=corporate,dc=com',
    searchFilter: '(&(objectcategory=person)(objectclass=user)(|(samaccountname={{username}})(mail={{username}})))',
    searchAttributes: ['displayName', 'mail'],
    tlsOptions: {
      ca: [
        fs.readFileSync('/path/to/root_ca_cert.crt')
      ]
    }
  }
};
...
```

## `credentialsLookup`

A synchronous function that receives the `req` object and returns an objec with keys `username` and `password` (or `name` and `pass`) can be provided. Note, that when this is provided the default lookup is not performed. This can be used to eg. enable basic auth header support:

```javascript
var basicAuth = require('basic-auth');
var ldapOpts = {
  server: { ... },
  credentialsLookup: basicAuth
}
```

## Asynchronous configuration retrieval

Instead of providing a static configuration object, you can pass a function as `options` that will take care of fetching the configuration. It will be called with the `req` object and a callback function having the standard `(err, result)` signature. Notice that the provided function will be called on every authenticate request.

```javascript
var getLDAPConfiguration = function(req, callback) {
  // Fetching things from database or whatever
  process.nextTick(function() {
    var opts = {
      server: {
        url: 'ldap://localhost:389',
        bindDN: 'cn=root',
        bindCredentials: 'secret',
        searchBase: 'ou=passport-ldapauth',
        searchFilter: '(uid={{username}})'
      }
    };

    callback(null, opts);
  });
};

var LdapStrategy = require('passport-ldapauth');

passport.use(new LdapStrategy(getLDAPConfiguration,
  function(user, done) {
    ...
    return done(null, user);
  }
));
```

## `ldapsearch`

[ldapsearch](http://linux.die.net/man/1/ldapsearch) is a great command line tool for testing your config. The user search query performed in the Express example above when user logging in has uid `john` is the same as the following `ldapsearch` call:

```bash
ldapsearch \
  -H ldap://localhost:389 \
  -x \
  -D cn=root \
  -w secret \
  -b ou=passport-ldapauth \
  "(uid=john)"
```

If the query does not return expected user the configuration is likely incorrect.

## License

MIT

`passport-ldapauth` has been partially sponsored by [Wakeone Ltd](https://wakeone.co/).
