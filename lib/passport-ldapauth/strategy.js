"use strict";

/**
 * Passport wrapper for ldapauth
 */
var passport = require('passport-strategy'),
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
 * - `passAuthOptionsToCallback`  when `true`, `options` from the passport.authenticate call will be the first argument to the verify callback (default: `false`)
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
 *           bindDn: 'cn=root',
 *           bindCredentials: 'secret',
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

/**
 * Options (passed when calling `passport.authenticate()`):
 * - `badRequestMessage`  flash message for missing username/password
 *                        (default: 'Missing credentials')
 * - `invalidCredentials`  flash message for InvalidCredentialsError, NoSuchObjectError,
 *                         and /no such user/ LDAP errors
 *                         (default: 'Invalid username/password')
 * - `userNotFound`  flash message when LDAP returns no error but also no user
 *                   (default: 'Invalid username/password')
 * - `constraintViolation`  flash message when user account is locked
 *                          (default: 'Exceeded password retry limit, account locked')
 */
var handleAuthentication = function(req, options) {
  var username, password, ldap;
  options || (options = {});

  username = lookup(req.body, this.options.usernameField) || lookup(req.query, this.options.usernameField);
  password = lookup(req.body, this.options.passwordField) || lookup(req.query, this.options.passwordField);

  if (!username || !password) {
    var auth = require('basic-auth');
    var credentials = auth(req);
    if (credentials) {
      username = credentials.name;
      password = credentials.pass;
    }
  }

  if (!username || !password) {
    return this.fail({message: options.badRequestMessage || 'Missing credentials'}, 400);
  }

  ldap = new LdapAuth(this.options.server);
  ldap.authenticate(username, password, function(err, user) {
    ldap.close(function(){}); // We don't care about the closing
    if (err) {
      // Invalid credentials / user not found are not errors but login failures
      if (err.name === 'InvalidCredentialsError' || err.name === 'NoSuchObjectError' || (typeof err === 'string' && err.match(/no such user/i))) {
        return this.fail({message: options.invalidCredentials || 'Invalid username/password'}, 401);
      }
      if (err.name === 'ConstraintViolationError'){
        return this.fail({message: options.constraintViolation || 'Exceeded password retry limit, account locked'}, 401);
      }
      // Other errors are (most likely) real errors
      return this.error(err);
    }

    if (!user) return this.fail({message: options.userNotFound || 'Invalid username/password'}, 401);

    // Execute given verify function
    if (this.verify) {
      if (this.options.passReqToCallback && this.options.passAuthOptionsToCallback) {
        return this.fail({message: options.passToCallback || 'Options passReqToCallback and passAuthOptionsToCallback cannot both be true'}, 401);
      } else if (this.options.passReqToCallback) {
        return this.verify(req, user, verify.call(this));
      } else if (this.options.passAuthOptionsToCallback) {
        return this.verify(options, user, verify.call(this));
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
  var callback = function(err, configuration) {
    if (err) return this.fail(err);

    this.options = setDefaults(configuration);
    handleAuthentication.call(this, req, options);
  };
  // Added functionality: getOptions can accept now up to 2 parameters
  if (this.getOptions.length ===1) { // Accepts 1 parameter, backwards compatibility
    this.getOptions(callback.bind(this));
  } else { // Accepts 2 parameters, pass request as well
    this.getOptions(req, callback.bind(this));
  }
};

module.exports = Strategy;
