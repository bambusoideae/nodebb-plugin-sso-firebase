define('admin/plugins/sso-firebase', ['settings'], function(Settings) {
	'use strict';
	/* globals $, app, socket, require */

	var ACP = {};

	ACP.init = function() {
		Settings.load('sso-firebase', $('.sso-firebase-settings'));

		// window.firebaseSettings = Settings;

		$('#save').on('click', function() {
			socket.emit('admin.settings.get', {hash: 'sso-firebase'}, function (err, values) {
				var needRestart = false;
				if (values['firebase-service-account'] !== $('.sso-firebase-settings input[name=firebase-service-account]').val() ||
					values['firebase-database-url'] !== $('.sso-firebase-settings input[name=firebase-database-url]').val()) {
					// Firebase App Settings is changed
					// You need restart app to reload firebase app config
					needRestart = true;
				}
				console.log('Require restart: ' + needRestart);

				Settings.save('sso-firebase', $('.sso-firebase-settings'), function() {
					if (needRestart) {
						app.alert({
							type: 'success',
							alert_id: 'sso-firebase-saved',
							title: 'Settings Saved',
							message: 'Please restart your NodeBB to apply these settings',
							clickfn: function() {
								socket.emit('admin.restart');
							}
						});
					} else {
						app.alert({
							type: 'success',
							alert_id: 'sso-firebase-saved',
							title: 'Settings Saved',
							message: 'Please reload your NodeBB to apply these settings',
							clickfn: function() {
								socket.emit('admin.reload');
							}
						});
					}
				});
			});


		});
	};

	return ACP;
});
