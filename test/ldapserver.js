var ldap = require('ldapjs');

authorize = function(req, res, next) {
  return next();
};

var SUFFIX = 'ou=passport-ldapauth';
var server = null;

db = {
  'valid': {
    dn: 'cn=valid, ou=passport-ldapauth',
    attributes:  {
      uid:  'valid',
      name: 'Valid User'
    }
  }
};

exports.start = function(port, cb) {
  if (server) {
    if (typeof cb === 'function') return cb();
    return;
  }

  server = ldap.createServer();

  server.bind('cn=root', function(req, res, next) {
    if (req.dn.toString() !== 'cn=root' || req.credentials !== 'secret') {
      return next(new ldap.InvalidCredentialsError());
    }
    res.end();
    return next();
  });

  server.bind(SUFFIX, authorize, function(req, res, next) {
    var dn = req.dn.toString();
    if (dn !== 'cn=valid, ou=passport-ldapauth' || req.credentials !== 'valid') {
      return next(new ldap.InvalidCredentialsError());
    }
    res.end();
    return next();
  });

  server.search(SUFFIX, authorize, function(req, res, next) {
    if (req.filter.attribute === 'uid' && req.filter.value === 'valid') {
      res.send(db['valid']);
    } else if (req.filter.attribute === 'uid' && req.filter.value === 'ms-ad') {
      return next(new ldap.InvalidCredentialsError("0090308: LdapErr: DSID-0C09030B, comment: AcceptSecurityContext error, data 533, v893 HEX: 0x533 - account disabled"));
    } else if (req.filter.attribute === 'member' && req.filter.value === db.valid.dn) {
      res.send({
        dn: 'cn=Group 1, ou=passport-ldapauth',
        attributes: {
          name: 'Group 1'
        }
      });
      res.send({
        dn: 'cn=Group 2, ou=passport-ldapauth',
        attributes: {
          name: 'Group 2'
        }
      });
    }
    res.end();
    return next();
  });

  server.listen(port, function() {
    if (typeof cb === 'function') return cb();
  });
};

exports.close = function(cb) {
  if (server) server.close();
  server = null;
  if (typeof cb === 'function') return cb();
  return;
};

if (!module.parent) {
  exports.start(1389);
}
