/**
 * Passport wrapper for ldapauth
 */
var passport = require('passport'),
    LdapAuth = require('ldapauth'),
    util     = require('util');

/**
 * Strategy constructor
 *
 * Options:
 * - `server`  options for ldapauth, see https://github.com/trentm/node-ldapauth
 * - `usernameField`  field name where the username is found, defaults to _username_
 * - `passwordField`  field name where the password is found, defaults to _password_
 * - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 */
function Strategy(options, verify) {
  if (!verify)  throw new Error('LDAP authentication strategy requires a verify function');
  if (!options) throw new Error('LDAP authentication strategy requires options');

  passport.Strategy.call(this);

  this.name    = 'ldapauth';
  this.options = options;
  this.verify  = verify;

  this.options.usernameField || (this.options.usernameField = 'username');
  this.options.passwordField || (this.options.passwordField = 'password');

  this.ldap = new LdapAuth(this.options.server);
};

util.inherits(Strategy, passport.Strategy);

// From passport-local
var lookup = function (obj, field) {
  if (!obj) { return null; }
  var chain = field.split(']').join('').split('[');
  for (var i = 0, len = chain.length; i < len; i++) {
    var prop = obj[chain[i]];
    if (typeof(prop) === 'undefined') { return null; }
    if (typeof(prop) !== 'object') { return prop; }
    obj = prop;
  }
  return null;
};

var verify = function(self) {
  // Callback given to user given verify function.
  return function(err, user, info) {
    if (err)   return self.error(err);
    if (!user) return self.fail(info);
    return self.success(user, info);
  };
};

Strategy.prototype.authenticate = function(req, options) {
  options || (options = {});

  var username = lookup(req.body, this.options.usernameField) || lookup(req.query, this.options.usernameField);
  var password = lookup(req.body, this.options.passwordField) || lookup(req.query, this.options.passwordField);

  if (!username || !password) return this.fail('Missing credentials');

  var self = this;
  self.ldap.authenticate(username, password, function(err, user) {
    if (err)   return self.error(err);
    if (!user) return self.fail('User not found');

    // Execute given verify function
    if (self.options.passReqToCallback) {
      return self.verify(req, user, verify(self));
    } else {
      return self.verify(user, verify(self));
    }
  });
};

module.exports = Strategy;
