define('admin/plugins/sso-firebase', ['settings'], function(Settings) {
	'use strict';
	/* globals $, app, socket, require */

	var ACP = {};

	ACP.init = function() {
		Settings.load('sso-firebase', $('.sso-firebase-settings'));

		$('#save').on('click', function() {
			Settings.save('sso-firebase', $('.sso-firebase-settings'), function() {
				app.alert({
					type: 'success',
					alert_id: 'sso-firebase-saved',
					title: 'Settings Saved',
					message: 'Please reload your NodeBB to apply these settings',
					clickfn: function() {
						socket.emit('admin.reload');
					}
				});
			});
		});
	};

	return ACP;
});
