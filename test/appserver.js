var express      = require('express'),
    passport     = require('passport'),
    LdapStrategy = require('passport-ldapauth').Strategy;

var server = null;

var init_passport = function(opts, testopts) {
  if (testopts.no_callback === true) {
    passport.use(new LdapStrategy(opts));
  } else {
    passport.use(new LdapStrategy(opts, function(user, cb) {
      return cb(null, user);
    }));
  }
};

exports.start = function(opts, testopts, cb) {

  var app = express();

  init_passport(opts, testopts);

  app.configure(function() {
    app.use(express.bodyParser());
    app.use(passport.initialize());
  });

  app.post('/login', passport.authenticate('ldapauth', {session: false}), function(req, res) {
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
