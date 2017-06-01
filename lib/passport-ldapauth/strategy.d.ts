// Type definitions for passport-ldapauth 2.0
// Project: https://github.com/vesse/passport-ldapauth
// Definitions by: Vesa Poikajärvi <https://github.com/vesse>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped
// TypeScript Version: 2.1

/// <reference types="node"/>

import { IncomingMessage } from 'http';
import { Options as LdapAuthOptions } from 'ldapauth-fork';
import {
    Strategy as PassportStrategy,
    AuthenticateOptions as PassportAuthenticateOptions
} from 'passport';

declare namespace Strategy {
    /**
     * Return value type for credentialsLookup
     */
    interface CredentialsLookupResult {
        username?: string;
        password?: string;
        user?: string;
        pass?: string;
    }

    /**
     * Credentials lookup function (eg. basic-auth)
     */
    type CredentialsLookup = (req: IncomingMessage) => CredentialsLookupResult;

    /**
     * Callback notified of an error when errors are handled as failures
     */
    type FailureErrorCallback = (err: any) => void;

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
        /**
         * Credentials lookup function to be used instead of default search from request
         */
        credentialsLookup?: CredentialsLookup;
        /**
         * Set to true to handle errors as login failures
         */
        handleErrorsAsFailures?: boolean;
        /**
         * Synchronous failure error callback for handling the failure if using handleErrorsAsFailures
         */
        failureErrorCallback?: FailureErrorCallback;
    }

    type OptionsFunctionCallback = (error: any, options: Options) => void;

    type OptionsFunction = (req: IncomingMessage, callback: OptionsFunctionCallback) => void;

    /**
     * Flash message localizations for authenticate
     */
    interface AuthenticateOptions extends PassportAuthenticateOptions {
        badRequestMessage?: string;
        invalidCredentials?: string;
        userNotFound?: string;
        constraintViolation?: string;
        invalidLogonHours?: string;
        invalidWorkstation?: string;
        passwordExpired?: string;
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
    type VerifyCallbackWithRequest = (req: IncomingMessage, user: any, callback: VerifyDoneCallback) => void;
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
    authenticate(req: IncomingMessage, options?: Strategy.AuthenticateOptions): void;
}

export = Strategy;
