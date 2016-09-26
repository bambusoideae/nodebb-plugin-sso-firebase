# nodebb-plugin-sso-firebase
SSO base on firebase for nodebb

NodeBB Hook
===========

  * action:auth.overrideLogin
  * static:app.load
  * filter:auth.init
  * filter:auth.list
  * filter:admin.header.build
  * filter:register.interstitial

How to use:
===========
  * Create a firebase project in the firebase console
  * Write a sso-server: just pass firebase token into nodebb website (ref: https://github.com/bambusoideae/firebase-sso-server-example)
  * Install this plugin in your forums

SSO Server:
===========
  * Create login page base on firebase auth
  * Pass firebase token back to your website

Auth flow:
==========
    * Login using Firebase (Nodebb Forums)
    * Redirect to: http://sso-server.example.com/login?response_type=token&redirect_uri=http%3A%2F%2Fnodebb-forums.example.org%2Fauth%2Ffirebase%2Fcallback
    * The user login with firebase auth
    * If login is succeeded -> Redirect to: http://nodebb-forums.example.org/auth/firebase/callback?token=accessToken
