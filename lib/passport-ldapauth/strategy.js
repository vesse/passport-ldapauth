'use strict';
var passport = require('passport-strategy');
var LdapAuth = require('ldapauth-fork');
var util     = require('util');

/**
 * Passport wrapper for ldapauth
 */


/**
 * Options callback callback (ie. the callback given if giving a callback
 * for options instead of an object)
 *
 * @callback optionsCallbackCallback
 * @param {(Error|undefined)} err - Possible error
 * @param {Object} options - Options object
 */
/**
 * Options callback
 *
 * @callback optionsCallback
 * @param {Object} req - HTTP request
 * @param {optionsCallbackCallback} callback - The callback returning the options
 */
/**
* Verify done callback
*
* @callback verifyDoneCallback
* @param {(Error|undefined)} err - Possible error
* @param {(Object|boolean)} user - The verified user or false if not allowed
* @param {Object} [info] info - Additional info message
*/
/**
* Found LDAP user verify callback
*
* @callback verifyCallback
* @param {Object} user - The user object from LDAP
* @param {verifyDoneCallback} callback - The verify callback
*/
/**
* Found LDAP user verify callback with request
*
* @callback verifyReqCallback
* @param {Object} req - The HTTP request
* @param {Object} user - The user object from LDAP
* @param {verifyDoneCallback} callback - The verify callback
*/
/**
 * @typedef credentialsLookupResult
 * @type {object}
 * @property {string} username - Username to use
 * @property {string} password - Password to use
 */
/**
 * @typedef credentialsLookupResultAlt
 * @type {object}
 * @property {string} user - Username to use
 * @property {string} pass - Password to use
 */
/**
 * Credentials lookup function
 *
 * @callback credentialsLookup
 * @param {Object} req - The HTTP request
 * @return {(credentialsLookupResult|credentialsLookupResultAlt)} - Found credentials
 */
/**
 * Synchronous function for doing something with an error if handling
 * errors as failures
 *
 * @callback failureErrorCallback
 * @param {Error} err - The error occurred
 */

/**
 * Add default values to options
 *
 * @private
 * @param {Object} options - Options object
 * @returns {Object} The given options with defaults filled
 */
var setDefaults = function(options) {
  options.usernameField || (options.usernameField = 'username');
  options.passwordField || (options.passwordField = 'password');
  return options;
};

/**
 * Strategy constructor
 * <br>
 *
 * The LDAP authentication strategy authenticates requests based on the
 * credentials submitted through an HTML-based login form.
 * <br>
 *
 * Applications may supply a `verify` callback which accepts `user` object
 * and then calls the `done` callback supplying a `user`, which should be set
 * to `false` if user is not allowed to authenticate. If an exception occured,
 * `err` should be set.
 * <br>
 *
 * Options can be also given as function that accepts a callback end calls it
 * with error and options arguments. Notice that the callback is executed on
 * every authenticate call.
 * <br>
 *
 * Example:
 * <pre>
 * var LdapStrategy = require('passport-ldapauth').Strategy;
 * passport.use(new LdapStrategy({
 *     server: {
 *       url: 'ldap://localhost:389',
 *       bindDN: 'cn=root',
 *       bindCredentials: 'secret',
 *       searchBase: 'ou=passport-ldapauth',
 *       searchFilter: '(uid={{username}})',
 *       reconnect: true
 *     }
 *   },
 *   function(user, done) {
 *     return cb(null, user);
 *   }
 * ));
 * </pre>
 * @constructor
 * @param {(Object|optionsCallback)} options - Configuration options or options returning function
 * @param {Object} options.server - [ldapauth-fork options]{@link https://github.com/vesse/node-ldapauth-fork}
 * @param {string} [options.usernameField=username] - Form field name for username
 * @param {string} [options.passwordField=password] - Form field name for password
 * @param {Number} [options.missingCredentialsStatus=400] - HTTP status code returned when credentials are missing from the request
 * @param {boolean} [options.passReqToCallback=false] - If true, request is passed to verify callback
 * @param {credentialsLookup} [options.credentialsLookup] - Credentials lookup function to use instead of default
 * @param {boolean} [options.handleErrorAsFailures=false] - Set to true to handle errors as login failures
 * @param {failureErrorCallback} [options.failureErrorCallback] - Function receives the occurred error when errors handled as failures
 * @param {(verifyCallback|verifyReqCallback|undefined)} [verify] - User verify callback
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

/* eslint-disable */
/**
 * Get value for given field from given object. Taken from passport-local,
 * copyright 2011-2013 Jared Hanson
 *
 * @private
 * @param {Object} obj - The HTTP request object
 * @param {string} field - The field name to look for
 * @returns {string|null} - Found value for the field or null
 */
var lookup = function(obj, field) {
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
/* eslint-enable */

/**
 * Verify the outcome of caller verify function - even if authentication (and
 * usually authorization) is taken care by LDAP there may be reasons why
 * a verify callback is provided, and again reasons why it may reject login
 * for a valid user.
 *
 * @private
 * @returns {undefined}
 */
var verify = function() {
  // Callback given to user given verify function.
  return function(err, user, info) {
    if (err) {
      return this.error(err);
    }
    if (!user) {
      return this.fail(info);
    }
    return this.success(user, info);
  }.bind(this);
};

/**
 * Execute failureErrorCallback if provided
 *
 * @private
 * @param {Error} err - The error occurred
 * @returns {undefined}
 */
var handleErrorAsFailure = function(err) {
  if (typeof this.options.failureErrorCallback === 'function') {
    this.options.failureErrorCallback(err);
  }
  return this.fail(err, 500);
};

/**
 * The actual authenticate implementation
 *
 * @private
 * @param {Object} req - The HTTP request
 * @param {Object} [options] - Flash messages
 * @returns {undefined}
 */
var handleAuthentication = function(req, options) {
  var username;
  var password;
  var ldap;
  var errorHandler;
  options || (options = {}); // eslint-disable-line no-param-reassign

  if (typeof this.options.credentialsLookup === 'function') {
    var credentials = this.options.credentialsLookup(req);
    if (credentials != null) {
      // name and pass as a courtesy for those who use basic-auth directly as
      // they're likely the main user group.
      username = credentials.username || credentials.name;
      password = credentials.password || credentials.pass;
    }
  } else {
    username = lookup(req.body, this.options.usernameField) || lookup(req.query, this.options.usernameField);
    password = lookup(req.body, this.options.passwordField) || lookup(req.query, this.options.passwordField);
  }

  if (!username || !password) {
    return this.fail({ message: options.badRequestMessage || 'Missing credentials' }, this.options.missingCredentialsStatus || 400);
  }

  errorHandler = this.options.handleErrorsAsFailures === true ? handleErrorAsFailure.bind(this) : this.error.bind(this);

  /**
   * AD possible messages
   * http://www-01.ibm.com/support/docview.wss?uid=swg21290631
   */
  var messages = {
    '530': options.invalidLogonHours || 'Not Permitted to login at this time',
    '531': options.invalidWorkstation || 'Not permited to logon at this workstation',
    '532': options.passwordExpired || 'Password expired',
    '533': options.accountDisabled || 'Account disabled',
    '534': options.accountDisabled || 'Account disabled',
    '701': options.accountExpired || 'Account expired',
    '773': options.passwordMustChange || 'User must reset password',
    '775': options.accountLockedOut || 'User account locked',
    default: options.invalidCredentials || 'Invalid username/password'
  };

  ldap = new LdapAuth(this.options.server);
  ldap.once('error', errorHandler);
  ldap.on('error', function() { /* Ignored */ });
  ldap.authenticate(username, password, function(err, user) {
    ldap.close(function(){
      // We don't care about the closing
    });

    if (err) {
      // Invalid credentials / user not found are not errors but login failures
      if (err.name === 'InvalidCredentialsError' || err.name === 'NoSuchObjectError' || (typeof err === 'string' && err.match(/no such user/i))) {
        var message;
        if (err.name === 'NoSuchObjectError') {
          message = options.noSuchObject || 'Bad search base';
        } else {
          message = options.invalidCredentials || 'Invalid username/password';
        }

        if (err.message) {
          var ldapComment = err.message.match(/data ([0-9a-fA-F]*), v[0-9a-fA-F]*/);
          if (ldapComment && ldapComment[1]){
            message = messages[ldapComment[1]] || messages['default'];
          }
        }
        return this.fail({ message: message }, 401);
      }
      if (err.name === 'ConstraintViolationError'){
        return this.fail({ message: options.constraintViolation || 'Exceeded password retry limit, account locked' }, 401);
      }

      // Other errors are (most likely) real errors
      return errorHandler(err);
    }

    if (!user) {
      return this.fail({ message: options.userNotFound || 'Invalid username/password' }, 401);
    }

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
 *
 * @param {Object} req - The HTTP request
 * @param {Object} [options] - Authentication options (flash messages). All messages have default values.
 * @param {string} [options.badRequestMessage] - Message for missing username/password
 * @param {string} [options.invalidCredentials] - Message for InvalidCredentialsError, NoSuchObjectError, and /no such user/ LDAP errors
 * @param {string} [options.userNotFound] - Message for user not found
 * @param {string} [options.constraintViolation] - Message when account is locked (or other constraint violation)
 * @param {string} [options.invalidLogonHours] - Message for Windows AD invalidLogonHours error
 * @param {string} [options.invalidWorkstation] - Message for Windows AD invalidWorkstation error
 * @param {string} [options.passwordExpired] - Message for Windows AD passwordExpired error
 * @param {string} [options.accountDisabled] - Message for Windows AD accountDisabled error
 * @param {string} [options.accountExpired] - Message for Windows AD accountExpired error
 * @param {string} [options.passwordMustChange] - Message for Windows AD passwordMustChange error
 * @param {string} [options.accountLockedOut] - Message for Windows AD accountLockedOut error
 * @returns {undefined}
 */
Strategy.prototype.authenticate = function(req, options) {
  if ((typeof this.options === 'object') && (!this.getOptions)) {
    return handleAuthentication.call(this, req, options);
  }

  var callback = function(err, configuration) {
    if (err) {
      return this.fail(err);
    }

    this.options = setDefaults(configuration);
    handleAuthentication.call(this, req, options);
  };

  // Added functionality: getOptions can accept now up to 2 parameters
  if (this.getOptions.length === 1) { // Accepts 1 parameter, backwards compatibility
    this.getOptions(callback.bind(this));
  } else { // Accepts 2 parameters, pass request as well
    this.getOptions(req, callback.bind(this));
  }
};

module.exports = Strategy;
