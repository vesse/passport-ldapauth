var express      = require('express'),
    passport     = require('passport'),
    LdapStrategy = require('passport-ldapauth').Strategy;

var server = null;

var init_passport = function(opts, no_callback) {
  passport.serializeUser(function(user, cb) {
    return cb(null, 'dummykey');
  });

  if (no_callback) {
    passport.use(new LdapStrategy(opts));
  } else {
    passport.use(new LdapStrategy(opts, function(user, cb) {
      return cb(null, user);
    }));
  }
};

exports.start = function(opts, no_callback, cb) {

  var app = express();

  init_passport(opts, no_callback);

  app.configure(function() {
    app.use(express.bodyParser());
    app.use(passport.initialize());
  });

  app.post('/login', passport.authenticate('ldapauth'), function(req, res) {
    res.send({status: 'ok'});
  });

  if (typeof cb === 'function') return cb(app);
  return;
};

exports.close = function(cb) {
  if (server) server.close();
  server = null;
  if (typeof cb === 'function') return cb();
  return;
};
