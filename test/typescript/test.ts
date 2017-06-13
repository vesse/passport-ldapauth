/**
 * Just a test file that should compile properly with tsc
 */
import * as Passport from 'passport';
import * as LdapStrategy from '../../';
import * as Express from 'express';
import { Request } from 'express';
import * as Logger from 'bunyan';
import * as BasicAuth from 'basic-auth';

const app = Express();

interface User {
    dn: string;
    foo?: boolean;
}

const user: User = { dn: 'test' };

const log = new Logger({
    name: 'ldap',
    component: 'client',
    stream: process.stderr,
    level: 'trace'
});

const options: LdapStrategy.Options = {
    server: {
        url: 'ldap://ldap.forumsys.com:389',
        bindDN: 'cn=read-only-admin,dc=example,dc=com',
        bindCredentials: 'password',
        searchBase: 'dc=example,dc=com',
        searchFilter: '(uid={{username}})',
        log: log,
        cache: true,
        includeRaw: true,
        groupSearchFilter: '(member={{dn}})',
        groupSearchBase: 'dc=example,dc=com'
    },
    credentialsLookup: BasicAuth
}

const optionsAsFunction: LdapStrategy.OptionsFunction = (req: Request, callback: LdapStrategy.OptionsFunctionCallback) => {
    callback(null, options);
}

const regularCallback: LdapStrategy.VerifyCallback = (user: User, callback: LdapStrategy.VerifyDoneCallback) => {
    if (user.foo) {
        callback(new Error('Foo user is an error'), null, { message: 'Foo user' });
    } else if (!user) {
        callback(null, false, { message: 'No user' });
    } else {
        callback(null, user);
    }
}

const reqCallback: LdapStrategy.VerifyCallbackWithRequest = (req: Request, user: User, callback: LdapStrategy.VerifyDoneCallback) => {
    if (user.foo) {
        callback(new Error('Foo user is an error'), null, { message: 'Foo user' });
    } else if (!user) {
        callback(null, false, { message: 'No user' });
    } else {
        callback(null, user);
    }
}

const credentialsLookup: LdapStrategy.CredentialsLookup = (req: Request): LdapStrategy.CredentialsLookupResult => ({
    user: 'username',
    pass: 'password'
});

Passport.serializeUser((user: User, done) => done(null, user.dn));
Passport.deserializeUser((dn, done) => done(null, user));

Passport.use(new LdapStrategy(options, regularCallback));
Passport.use('withreq', new LdapStrategy(options, reqCallback));
Passport.use('dynopts', new LdapStrategy(optionsAsFunction));

const authOpts: LdapStrategy.AuthenticateOptions = {
    badRequestMessage: 'Bad request you did there'
}

app.post('/login', Passport.authenticate('ldapauth', authOpts));

app.post('/login', (req, res, next) => {
    Passport.authenticate('ldapauth', (err: Error, user: User) => {
        req.logIn(user, (err: Error) => {
            res.send({ok: 1});
        })
    })(req, res, next);
});
