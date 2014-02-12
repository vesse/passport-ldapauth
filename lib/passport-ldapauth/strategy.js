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
 * Options can be also given as function that accepts a callback end calls it
 * with error and options arguments. Notice that the callback is executed on
 * every authenticate call.
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
  // We now accept function as options as well so we cannot assume anymore
  // that a call with a function parameter only would have skipped options
  // and just provided a verify callback
  if (!options) {
    throw new Error('LDAP authentication strategy requires options');
  }

  this.options    = null;
  this.getOptions = null;

  if (typeof options === 'object') {
    this.options = setDefaults(options);
  } else if (typeof options === 'function') {
    this.getOptions = options;
  }

  passport.Strategy.call(this);

  this.name   = 'ldapauth';
  this.verify = verify;
};

util.inherits(Strategy, passport.Strategy);

/**
 * Add default values to options
 *
 * @param options
 * @returns {*}
 */
var setDefaults = function(options) {
  options.usernameField || (options.usernameField = 'username');
  options.passwordField || (options.passwordField = 'password');
  return options;
};

/**
 * Get value for given field from given object. Taken from passport-local,
 * copyright 2011-2013 Jared Hanson
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
var verify = function() {
  // Callback given to user given verify function.
  return function(err, user, info) {
    if (err)   return this.error(err);
    if (!user) return this.fail(info);
    return this.success(user, info);
  }.bind(this);
};

var handleAuthentication = function(req, options) {
  var username, password, ldap;
  options || (options = {});

  username = lookup(req.body, this.options.usernameField) || lookup(req.query, this.options.usernameField);
  password = lookup(req.body, this.options.passwordField) || lookup(req.query, this.options.passwordField);

  if (!username || !password) return this.fail('Missing credentials');

  ldap = new LdapAuth(this.options.server);
  ldap.authenticate(username, password, function(err, user) {
    ldap.close(function(){}); // We don't care about the closing
    if (err) {
      // Invalid credentials / user not found are not errors but login failures
      if (err.name === 'InvalidCredentialsError' || err.name === 'NoSuchObjectError' || (typeof err === 'string' && err.match(/no such user/i))) {
        return this.fail('Invalid username/password');
      }
      // Other errors are (most likely) real errors
      return this.error(err);
    }

    if (!user) return this.fail('User not found');

    // Execute given verify function
    if (this.verify) {
      if (this.options.passReqToCallback) {
        return this.verify(req, user, verify.call(this));
      } else {
        return this.verify(user, verify.call(this));
      }
    } else {
      return this.success(user);
    }
  }.bind(this));
};

/**
 * Authenticate the request coming from a form or such.
 */
Strategy.prototype.authenticate = function(req, options) {
  if ((typeof this.options === 'object') && (!this.getOptions)) {
    return handleAuthentication.call(this, req, options);
  }

  this.getOptions(function(err, configuration) {
    if (err) return this.fail(err);

    this.options = setDefaults(configuration);
    handleAuthentication.call(this, req, options);
  }.bind(this));
};

module.exports = Strategy;
