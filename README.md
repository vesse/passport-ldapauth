# passport-ldapauth

[Passport](http://passportjs.org/) authentication strategy against LDAP server. This module is a Passport strategy wrapper for [ldapauth-fork](https://github.com/vesse/node-ldapauth-fork)

## Usage

```javascript
var LdapStrategy = require('passport-ldapauth').Strategy;

passport.use(new LdapStrategy({
    server: {
      url: 'ldap://localhost:389',
      ...
    }
  }));
```

If you wish to e.g. do some additional verification or initialize user data to local database you may supply a `verify` callback which accepts `user` object and then calls the `done` callback supplying a `user`, which should be set to `false` if user is not allowed to authenticate. If an exception occured, `err` should be set.

```javascript
var LdapStrategy = require('passport-ldapauth').Strategy;

passport.use(new LdapStrategy({
    server: {
      url: 'ldap://localhost:389',
      ...
    }
  },
  function(user, done) {
    ...
    return done(null, user);
  }
));
```

## Install

```
npm install passport-ldapauth
```

## Status

[![Build Status](https://travis-ci.org/vesse/passport-ldapauth.png)](https://travis-ci.org/vesse/passport-ldapauth)
[![Dependency Status](https://gemnasium.com/vesse/passport-ldapauth.png)](https://gemnasium.com/vesse/passport-ldapauth)

## Configuration options

* `server`: LDAP settings. These are passed directly to [ldapauth-fork](https://github.com/vesse/node-ldapauth-fork). See its documentation for all available options.
    * `url`: e.g. `ldap://localhost:389`
    * `adminDn`: e.g. `cn='root'`
    * `adminPassword`: Password for adminDn
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

## Express example

```javascript
var express      = require('express'),
    passport     = require('passport'),
    LdapStrategy = require('passport-ldapauth').Strategy;

var OPTS = {
  server: {
    url: 'ldap://localhost:389',
    adminDn: 'cn=root',
    adminPassword: 'secret',
    searchBase: 'ou=passport-ldapauth',
    searchFilter: '(uid={{username}})'
  }
};

var app = express();

passport.use(new LdapStrategy(OPTS));

app.configure(function() {
  app.use(express.bodyParser());
  app.use(passport.initialize());
});

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
    adminDn: 'non-person@corporate.com',
    adminPassword: 'secret',
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
## Asynchronous configuration retrieval

Instead of providing a static configuration object, you can pass to the LdapStrategy a function that will take care of fetching the configuration.

Example (here process.nextTick illustrates the asynchronous workings; in a real world this will for example be a database query):

```javascript
function getLDAPConfiguration(callback) {
  process.nextTick(function() {
    var opts = {
      server: {
        url: 'ldap://localhost:389',
        adminDn: 'cn=root',
        adminPassword: 'secret',
        searchBase: 'ou=passport-ldapauth',
        searchFilter: '(uid={{username}})'
      }
    };
    callback(null, opts);
  });
}

var LdapStrategy = require('passport-ldapauth').Strategy;

passport.use(new LdapStrategy(getLDAPConfiguration,
  function(user, done) {
    ...
    return done(null, user);
  }
));
```

## License

MIT
