var express      = require('express'),
    passport     = require('passport'),
    LdapStrategy = require('passport-ldapauth').Strategy;

var server = null;

var init_passport = function(ldap_port) {

};

exports.start = function(ldap_port, cb) {

  var app = express();

  init_passport(ldap_port);

  app.configure(function() {
    app.use(passport.initialize());
  });

  app.post('/login', passport.authenticate('ldapauth'), function(req, res) {
    res.send({status: 'ok'});
  });

  if (typeof cb === 'function') return cb();
  return;
};

exports.close = function(cb) {
  if (server) server.close();
  server = null;
  if (typeof cb === 'function') return cb();
  return;
};
