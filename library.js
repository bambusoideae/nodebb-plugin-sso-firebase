(function(module) {
	"use strict";

	var User = module.parent.require('./user'),
		meta = module.parent.require('./meta'),
		db = module.parent.require('../src/database'),
		passport = module.parent.require('passport');
	var utils = module.parent.require('../public/src/utils');
	var	passportFirebase = require('./lib/passport-firebase-auth').Strategy;
	var	fs = module.parent.require('fs'),
		path = module.parent.require('path'),
		nconf = module.parent.require('nconf'),
		async = module.parent.require('async');

	var authenticationController = module.parent.require('./controllers/authentication');

	var constants = Object.freeze({
		'name': "Firebase",
		'admin': {
			'route': '/plugins/sso-firebase',
			'icon': 'fa-sign-in'
		}
	});

	var Firebase = {};

	Firebase.init = function(data, callback) {
		function render(req, res, next) {
			res.render('admin/plugins/sso-firebase', {});
		}

		data.router.get('/admin/plugins/sso-firebase', data.middleware.admin.buildHeader, render);
		data.router.get('/api/admin/plugins/sso-firebase', render);

		callback();
	}

	Firebase.getStrategy = function(strategies, callback) {
		meta.settings.get('sso-firebase', function(err, settings) {
			if (!err && settings['firebase-service-account'] && settings['firebase-database-url'] && settings['firebase-project-id'] && settings['authorizationurl'] &&
						settings['allowFirebaseLogin'] && settings['allowFirebaseLogin'] === "on") {

				passport.use(new passportFirebase({
					firebaseConfig: {
 	              		serviceAccount: settings['firebase-service-account'],
               			databaseURL: settings['firebase-database-url']
          			},
					firebaseProjectId: settings['firebase-project-id'],
					authorizationURL: settings['authorizationurl'],
					callbackURL: nconf.get('url') + '/auth/firebase/callback',
					passReqToCallback: true
				}, function(req, accessToken, refreshToken, decodedToken, done) {
					if (req.hasOwnProperty('user') && req.user.hasOwnProperty('uid') && req.user.uid > 0) {
						// Save Google Firebase specific information to the user
						User.setUserField(req.user.uid, 'firebaseid', decodedToken.uid);
						db.setObjectField('firebaseid:uid', decodedToken.uid, req.user.uid);
						return done(null, req.user);
					}

					Firebase.login(decodedToken.uid, decodedToken.name, decodedToken.email, decodedToken.picture, function(err, user) {
						if (err) {
							return done(err);
						}

						authenticationController.onSuccessfulLogin(req, user.uid);
						done(null, user);
					});
				}));

				strategies.push({
					name: 'firebaseauth',
					url: '/auth/firebase',
					callbackURL: '/auth/firebase/callback',
					icon: constants.admin.icon,
					scope: 'firebase',
					prompt: 'select_account'
				});
			}

			callback(null, strategies);
		});
	};

	Firebase.getAssociation = function(data, callback) {
		User.getUserField(data.uid, 'firebaseid', function(err, firebaseid) {
			if (err) {
				return callback(err, data);
			}

			if (firebaseid) {
				data.associations.push({
					associated: true,
					url: nconf.get('url') + '/auth/firebase-account-info/' + firebaseid,
					name: constants.name,
					icon: constants.admin.icon
				});
			} else {
				data.associations.push({
					associated: false,
					url: nconf.get('url') + '/auth/firebase',
					name: constants.name,
					icon: constants.admin.icon
				});
			}

			callback(null, data);
		})
	};

	Firebase.login = function(firebaseid, name, email, picture, callback) {
		Firebase.getUidByFirebaseId(firebaseid, function(err, uid) {
			if(err) {
				return callback(err);
			}

			if (uid !== null) {
				// Existing User
				callback(null, {
					uid: uid
				});
			} else {
				// Check settings
				meta.settings.get('sso-firebase', function(err, settings) {
					if (err) {
						return callback(err);
					}

					if (!settings['allowFirebaseRegister'] || (settings['allowFirebaseRegister'] && settings['allowFirebaseRegister'] === "off")) {
						return callback({ message: 'Register is disable.' });
					}

					// New User
					var success = function(uid) {
						// meta.settings.get('sso-firebase', function(err, settings) {
						var autoConfirm = settings && settings['autoconfirm'] === "on" ? 1 : 0;
						User.setUserField(uid, 'email:confirmed', autoConfirm);
						// Save google firebase specific information to the user
						User.setUserField(uid, 'firebaseid', firebaseid);
						db.setObjectField('firebaseid:uid', firebaseid, uid);

						// Save their photo, if present
						if (picture) {
							User.setUserField(uid, 'uploadedpicture', picture);
							User.setUserField(uid, 'picture', picture);
						}

						callback(null, {
							uid: uid
						});

						// });
					};

					User.getUidByEmail(email, function(err, uid) {
						if(err) {
							return callback(err);
						}

						if (!uid) {
							// Try to create user from email
							var emailRegEx = /([a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/;
							var username = "";
							var emailParse = emailRegEx.exec(email);

							if (emailParse) {
								username = emailParse[1];
							}

							if (!utils.isUserNameValid(username)) {
								username = firebaseid;
							}

							// Create new user
							User.create({username: username, email: email, fullname: name}, function(err, uid) {
								if(err) {
									return callback(err);
								}

								success(uid);
							});
						} else {
							success(uid); // Existing account -- merge
						}
					});
				});
			}
		});
	};

	Firebase.getUidByFirebaseId = function(firebaseid, callback) {
		db.getObjectField('firebaseid:uid', firebaseid, function(err, uid) {
			if (err) {
				return callback(err);
			}
			callback(null, uid);
		});
	};

	Firebase.addMenuItem = function(custom_header, callback) {
		custom_header.authentication.push({
			"route": constants.admin.route,
			"icon": constants.admin.icon,
			"name": constants.name
		});

		callback(null, custom_header);
	}

	Firebase.deleteUserData = function(data, callback) {
		var uid = data.uid;

		async.waterfall([
			async.apply(User.getUserField, uid, 'firebaseid'),
			function(oAuthIdToDelete, next) {
				db.deleteObjectField('firebaseid:uid', oAuthIdToDelete, next);
			}
		], function(err) {
			if (err) {
				winston.error('[sso-firebase] Could not remove auth data for uid ' + uid + '. Error: ' + err);
				return callback(err);
			}
			callback(null, uid);
		});
	};

	module.exports = Firebase;
}(module));
