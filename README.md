# passport-ldapauth

[Passport](http://passportjs.org/) authentication strategy against LDAP server. This module is a Passport strategy wrapper for [ldapauth-fork](https://github.com/vesse/node-ldapauth-fork)

## Install

```
npm install passport-ldapauth
```

## Status

[![Build Status](https://travis-ci.org/vesse/passport-ldapauth.png)](https://travis-ci.org/vesse/passport-ldapauth)
[![Dependency Status](https://gemnasium.com/vesse/passport-ldapauth.png)](https://gemnasium.com/vesse/passport-ldapauth)

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
    * `bindDn`: e.g. `cn='root'`
    * `bindCredentials`: Password for bindDn
    * `searchBase`: e.g. `o=users,o=example.com`
    * `searchFilter`:  LDAP search filter, e.g. `(uid={{username}})`. Use literal `{{username}}` to have the given username used in the search.
    * `searchAttributes`: Optional array of attributes to fetch from LDAP server, e.g. `['displayName', 'mail']`. Defaults to `undefined`, i.e. fetch all attributes
    * `tlsOptions`: Optional object with options accepted by Node.js [tls](http://nodejs.org/api/tls.html#tls_tls_connect_options_callback) module.
* `usernameField`: Field name where the username is found, defaults to _username_
* `passwordField`: Field name where the password is found, defaults to _password_
* `passReqToCallback`: When `true`, `req` is the first argument to the verify callback (default: `false`):

        passport.use(new LdapStrategy(..., function(req, user, done) {
            ...
            done(null, user);
          }
        ));

Note: you can pass a function instead of an object as `options`, see the [example below](#options-as-function)

### Authenticate requests

Use `passport.authenticate()`, specifying the `'ldapauth'` strategy, to authenticate requests.

#### `authenticate()` options

In addition to [default authentication options](http://passportjs.org/guide/authenticate/) the following options are available for `passport.authenticate()`:

 * `badRequestMessage`  flash message for missing username/password (default: 'Missing credentials')
 * `invalidCredentials`  flash message for `InvalidCredentialsError`, `NoSuchObjectError`, and `/no such user/i` LDAP errors (default: 'Invalid username/password')
 * `userNotFound`  flash message when LDAP returns no error but also no user (default: 'Invalid username/password')

## Express example

```javascript
var express      = require('express'),
    passport     = require('passport'),
    bodyParser   = require('body-parser'),
    LdapStrategy = require('passport-ldapauth');

var OPTS = {
  server: {
    url: 'ldap://localhost:389',
    bindDn: 'cn=root',
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
    bindDn: 'cn=non-person,ou=system,dc=corp,dc=corporate,dc=com',
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

<a name="options-as-function"></a>
## Asynchronous configuration retrieval

Instead of providing a static configuration object, you can pass a function as `options` that will take care of fetching the configuration. It will be called with a callback function having the standard `(err, result)` signature. Notice that the provided function will be called on every authenticate request.

```javascript
var getLDAPConfiguration = function(req, callback) {
  // Fetching things from database or whatever
  process.nextTick(function() {
    var opts = {
      server: {
        url: 'ldap://localhost:389',
        bindDn: 'cn=root',
        bindCredentials: 'secret',
        searchBase: 'ou=passport-ldapauth',
        searchFilter: '(uid={{username}})'
      }
    };
    
    //OR
    
    var opts = fetchConfigFromDB(req.body.ldapServerId);
    
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

## License

MIT
