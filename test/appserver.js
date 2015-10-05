var express      = require('express'),
    passport     = require('passport'),
    LdapStrategy = require('passport-ldapauth').Strategy,
    bodyParser   = require('body-parser');

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

passport.serializeUser(function(user, cb) {
  cb(null, user.dn);
});

passport.deserializeUser(function(dn, cb) {
  cb(null, {dn: dn});
});

exports.start = function(opts, testopts, cb) {

  var app = express();

  init_passport(opts, testopts);

  app.use(bodyParser.json());
  app.use(passport.initialize());

  app.post('/login', passport.authenticate('ldapauth', {session: false}), function(req, res) {
    res.send({status: 'ok'});
  });

  app.post('/custom-cb-login', function(req, res, next) {
    passport.authenticate('ldapauth', function(err, user, info) {
      if (err) return next(err);
      if (!user) return res.status(401).send(info);
      req.logIn(user, function(err) {
        if (err) return next(err);
        return res.json(user);
      })
    })(req, res, next);
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
