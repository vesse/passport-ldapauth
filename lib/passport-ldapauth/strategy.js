"use strict";

/**
 * Passport wrapper for ldapauth
 */
var passport = require('passport'),
    LdapAuth = require('ldapauth-fork'),
    util     = require('util');

/**
 * Strategy constructor
 *
 * The LDAP authentication strategy authenticates requests based on the
 * credentials submitted through an HTML-based login form.
 *
 * Applications may supply a `verify` callback which accepts `user` object
 * and then calls the `done` callback supplying a `user`, which should be set
 * to `false` if user is not allowed to authenticate. If an exception occured,
 * `err` should be set.
 *
 * Options:
 * - `server`  options for ldapauth, see https://github.com/trentm/node-ldapauth
 * - `usernameField`  field name where the username is found, defaults to _username_
 * - `passwordField`  field name where the password is found, defaults to _password_
 * - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Example:
 *
 *     var LdapStrategy = require('passport-ldapauth').Strategy;
 *     passport.use(new LdapStrategy({
 *         server: {
 *           url: 'ldap://localhost:389',
 *           adminDn: 'cn=root',
 *           adminPassword: 'secret',
 *           searchBase: 'ou=passport-ldapauth',
 *           searchFilter: '(uid={{username}})'
 *         }
 *       },
 *       function(user, done) {
 *         return cb(null, user);
 *       }
 *     ));
 */
var Strategy = function(options, verify) {
  if (typeof options === 'function') {
    verify  = options;
    options = undefined;
  }

  if (!options) throw new Error('LDAP authentication strategy requires options');

  passport.Strategy.call(this);

  this.name    = 'ldapauth';
  this.options = options;
  this.verify  = verify;

  this.options.usernameField || (this.options.usernameField = 'username');
  this.options.passwordField || (this.options.passwordField = 'password');
};

util.inherits(Strategy, passport.Strategy);

/**
 * Get value for given field from given object. Taken from passport-local
 */
var lookup = function (obj, field) {
  var i, len, chain, prop;
  if (!obj) { return null; }
  chain = field.split(']').join('').split('[');
  for (i = 0, len = chain.length; i < len; i++) {
    prop = obj[chain[i]];
    if (typeof(prop) === 'undefined') { return null; }
    if (typeof(prop) !== 'object') { return prop; }
    obj = prop;
  }
  return null;
};

/**
 * Verify the outcome of caller verify function - even if authentication (and
 * usually authorization) is taken care by LDAP there may be reasons why
 * a verify callback is provided, and again reasons why it may reject login
 * for a valid user.
 */
var verify = function(self) {
  // Callback given to user given verify function.
  return function(err, user, info) {
    if (err)   return self.error(err);
    if (!user) return self.fail(info);
    return self.success(user, info);
  };
};

/**
 * Authenticate the request coming from a form or such.
 */
Strategy.prototype.authenticate = function(req, options) {
  var username, password, ldap, self;
  options || (options = {});

  username = lookup(req.body, this.options.usernameField) || lookup(req.query, this.options.usernameField);
  password = lookup(req.body, this.options.passwordField) || lookup(req.query, this.options.passwordField);

  if (!username || !password) return this.fail('Missing credentials');

  self = this;
  ldap = new LdapAuth(self.options.server);
  ldap.authenticate(username, password, function(err, user) {
    ldap.close(function(){}); // We don't care about the closing
    if (err) {
      // Invalid credentials / user not found are not errors but login failures
      if (err.name === 'InvalidCredentialsError' || (typeof err === 'string' && err.match(/no such user/i))) {
        return self.fail('Invalid username/password');
      }
      // Other errors are (most likely) real errors
      return self.error(err);
    }

    if (!user) return self.fail('User not found');

    // Execute given verify function
    if (self.verify) {
      if (self.options.passReqToCallback) {
        return self.verify(req, user, verify(self));
      } else {
        return self.verify(user, verify(self));
      }
    } else {
      return self.success(user);
    }
  });
};

module.exports = Strategy;
