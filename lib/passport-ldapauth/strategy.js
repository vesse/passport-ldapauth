/**
 * Passport wrapper for ldapauth
 */
var passport = require('passport'),
    ldapauth = require('ldapauth'),
    util     = require('util');

function Strategy(options, verify) {
  passport.Strategy.call(this);
};

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, options) {

};

module.exports = Strategy;
