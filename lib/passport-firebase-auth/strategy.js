"use strict";

// Load modules.
let passport = require('passport-strategy')
let util = require('util');
let url = require('url');
let firebaseAdmin = require('firebase-admin');
let querystring = require('querystring');

let utils = require('./utils');
let NullStateStore = require('./state/null');
let SessionStateStore = require('./state/session');
// let FirebaseProfile = require('./profile/firebase');
let AuthorizationError = require('./errors/authorizationerror')
let TokenError = require('./errors/tokenerror')
let InternalAuthError = require('./errors/internalautherror');

/**
 * `Strategy` constructor.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `cb`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `firebaseConfig` your Firebase config file
 *   - `callbackURL`    URL to which Firebase will redirect the user after granting authorization
 * 
 * Notes:
 *   - You must call 
 *          firebase.initializeApp({
 *              serviceAccount: "path/to/serviceAccountCredentials.json",
 *              databaseURL: "https://databaseName.firebaseio.com"
 *          });
 *      before using this strategy.
 * 
 * Examples:
 *
 *     passport.use(new GoogleStrategy({
 *         firebaseProjectId: "project-id",
 *         authorizationURL: 'https://account.example.net/auth',
 *         callbackURL: 'https://www.example.net/auth/firebase/callback'
 *       },
 *       function(accessToken, refreshToken, decodedToken, cb) {
 *         User.findOrCreate(..., function (err, user) {
 *           cb(err, user);
 *         });
 *       }
 *     ));
 *      
 *      decodedToken: {
 *          iss: 'https://securetoken.google.com/<projectId>',
 *          name: 'Full Name',
 *          picture: 'picture_url',
 *          aud: '<projectId>',
 *          auth_time: time,
 *          user_id: 'user_id',
 *          sub: 'uid of user or device',
 *          iat: issued-at-time,
 *          exp: expiration-time,
 *          email: user-email,
 *          email_verified: true/false,
 *          firebase: {
 *              identities: {}
 *          },
 *          uid: uid
 *      }
 * 
 * 
 * @constructor
 * @param {object} options
 * @param {function} verify
 * @access public
 */
function FirebaseStrategy(options, verify) {
    if (typeof options === 'function') {
        verify = options;
        options = undefined;
    }
    options = options || {};

    if (!verify) { throw new TypeError('FirebaseStrategy requires a verify callback'); }
    if (!options.authorizationURL) { throw new TypeError('FirebaseStrategy requires a authorizationURL option'); }
    if (!options.firebaseProjectId) { throw new TypeError('FirebaseStrategy requires a project id'); }

    passport.Strategy.call(this);
    this.name = 'firebaseauth';
    this._verify = verify;

    this._callbackURL = options.callbackURL;
    this._scope = options.scope;
    this._scopeSeparator = options.scopeSeparator || ' ';
    this._key = options.sessionKey || ('firebaseauth:' + url.parse(options.authorizationURL).hostname);

    this._firebaseProjectId = options.firebaseProjectId;
    this._firebaseIssuer = "https://securetoken.google.com/" + options.firebaseProjectId;
    this._authorizationURL = options.authorizationURL;

    // CSRF Store
    if (options.store) {
        this._stateStore = options.store;
    } else {
        if (options.state) {
            // Internal Session store
            this._stateStore = new SessionStateStore({ key: this._key });
        } else {
            // Without CSRF
            this._stateStore = new NullStateStore();
        }
    }
    this._trustProxy = options.proxy;
    this._passReqToCallback = options.passReqToCallback;
    this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;
}

// Inherit from `passport.Strategy`.
util.inherits(FirebaseStrategy, passport.Strategy);

/**
 * Authenticate request by delegating to a service provider using Firebase Authenticate.
 *
 * @param {Object} req
 * @api protected
 */
FirebaseStrategy.prototype.authenticate = function(req, options) {
    options = options || {};
    let self = this;

    if (req.query && req.query.error) {
        if (req.query.error == 'access_denied') {
            return this.fail({ message: req.query.error_description });
        } else {
            return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
        }
    }

    let callbackURL = options.callbackURL || this._callbackURL;
    if (callbackURL) {
        let parsed = url.parse(callbackURL);
        if (!parsed.protocol) {
            // The callback URL is relative, resolve a fully qualified URL from the
            // URL of the originating request.
            callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
        }
    }
    
    let meta = {
        authorizationURL: this.authorizationURL,
        key: this._key
    }

    // callbackURL: 'https://www.example.net/auth/firebase/callback'
    // GET/POST: /auth/firebase/callback?token=firebase_token&state=session_state
    if (req.query && req.query.token) {
        function loaded(err, ok, state) {
            if (err) { return self.error(err); }
            if (!ok) {
                return self.fail(state, 403);
            }
        
            let idToken = req.query.token;

            let params = self.tokenParams(options);
            params.grant_type = 'authorization_token';
            if (callbackURL) { params.redirect_uri = callbackURL; }

            // idToken comes from the client app (shown above)
            firebaseAdmin.auth().verifyIdToken(idToken).then(function(decodedToken) {
                // let uid = decodedToken.uid;
                // Check iss & aud
                if (decodedToken.iss !== self._firebaseIssuer && decodedToken.aud !== self._firebaseProjectId) {
                    return self.error(self._createAuthError('Incorrect firebase project id'));
                }

                // 
                function verified(err, user, info) {
                    if (err) { return self.error(err); }
                    if (!user) { return self.fail(info); }
                            
                    info = info || {};
                    if (state) { info.state = state; }
                    self.success(user, info);
                }

                try {
                    if (self._passReqToCallback) {
                        // let arity = self._verify.length;
                        // if (arity == 5) {
                        self._verify(req, idToken, null, decodedToken, verified);
                    } else {
                        // let arity = self._verify.length;
                        // if (arity == 5) {
                        self._verify(idToken, null, decodedToken, verified);
                    }
                } catch (ex) {
                    return self.error(ex);
                }
            }).catch(function(error) {
                // Handle error
                // return self.error(error);
                return self.error(self._createAuthError('Failed to obtain access token', err));
            });
        }
        
        let state = req.query.state;
        try {
            let arity = this._stateStore.verify.length;
            if (arity == 4) {
                this._stateStore.verify(req, state, meta, loaded);
            } else { // arity == 3
                this._stateStore.verify(req, state, loaded);
            }
        } catch (ex) {
            return this.error(ex);
        }
    } else {
        // SSO redirect
        let params = this.authorizationParams(options);
        params.response_type = 'token';
        if (callbackURL) { params.redirect_uri = callbackURL; }
        // let scope = options.scope || this._scope;
        // if (scope) {
        //     if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
        //     params.scope = scope;
        // }

        let state = options.state;
        if (state) {
            params.state = state;
            let location = self._authorizationURL + '?' + querystring.stringify(params);
            this.redirect(location);
        } else {
            function stored(err, state) {
                if (err) { return self.error(err); }

                if (state) { params.state = state; }
                let location = self._authorizationURL + '?' + querystring.stringify(params);
                self.redirect(location);
            }
            
            try {
                let arity = this._stateStore.store.length;
                if (arity == 3) {
                    this._stateStore.store(req, meta, stored);
                } else { // arity == 2
                    this._stateStore.store(req, stored);
                }
            } catch (ex) {
                return this.error(ex);
            }
        }
    }
};

/**
 * Return extra parameters to be included in the authorization request.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
FirebaseStrategy.prototype.authorizationParams = function(options) {
    return {};
};

/**
 * Return extra parameters to be included in the token request.
 *
 * @return {Object}
 * @api protected
 */
FirebaseStrategy.prototype.tokenParams = function(options) {
    return {};
};

/**
 * Create an Auth error.
 *
 * @param {String} message
 * @param {Object|Error} err
 * @api private
 */
FirebaseStrategy.prototype._createAuthError = function(message, err) {
  let e;
  if (err) {
      e = new TokenError(message, err);
  }
  if (!e) { e = new InternalAuthError(message, err); }
  return e;
};

/**
 * Export `FirebaseStrategy`.
 */
module.exports = FirebaseStrategy;
