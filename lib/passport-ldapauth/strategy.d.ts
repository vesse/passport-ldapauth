import { Request } from 'express';
import { Options as LdapAuthOptions } from 'ldapauth-fork';
import { Strategy as PassportStrategy, AuthenticateOptions } from 'passport';

declare namespace Strategy {
    /**
     * passport-ldapauth options
     */
    interface Options {
        /**
         * ldapauth-fork connection options
         */
        server: LdapAuthOptions;
        /**
         * Form field name for username (default: username)
         */
        usernameField?: string;
        /**
         * Form field name for password (default: password)
         */
        passwordField?: string;
        /**
         * If set to true, request is passed to verify callback
         */
        passReqToCallback?: boolean;
    }

    type OptionsFunctionCallback = (error: any, options: Options) => void;

    type OptionsFunction = (req: Request, callback: OptionsFunctionCallback) => void;

    /**
     * Flash message localizations for authenticate
     */
    interface AuthenticateOptions extends AuthenticateOptions {
        badRequestMessage?: string;
        invalidCredentials?: string;
        userNotFound?: string;
        constraintViolation?: string;
        invalidLogonHours?: string;
        invalidWorkstation?: string;
        passwordExpired?: string;
        accountDisabled?: string;
        accountDisabled?: string;
        accountExpired?: string;
        passwordMustChange?: string;
        accountLockedOut?: string;
    }

    /**
     * Options that verify done callback can pass
     */
    interface VerifyOptions {
        message: string;
    }

    /**
     * Callback executed by caller in the verify function
     */
    type VerifyDoneCallback = (error: any, user?: any, options?: VerifyOptions) => void;

    /**
     * Verify callback when passReqToCallback = false
     */
    type VerifyCallback = (user: any, callback: VerifyDoneCallback) => void;
    /**
     * Verify callback when passReqToCallback = true
     */
    type VerifyCallbackWithRequest = (req: Request, user: any, callback: VerifyDoneCallback) => void;
}

declare class Strategy implements PassportStrategy {
    /**
     * @param options
     * @param verify
     */
    constructor(options: Strategy.Options | Strategy.OptionsFunction, verify?: Strategy.VerifyCallback | Strategy.VerifyCallbackWithRequest);

    /**
     * Name of the strategy
     */
    name: string;

    /**
     * @param req
     * @param options
     */
    authenticate(req: Request, options?: Strategy.AuthenticateOptions): void;
}

export = Strategy;
