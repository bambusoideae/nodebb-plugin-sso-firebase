<div class="row">
	<div class="col-sm-2 col-xs-12 settings-header">Firebase SSO</div>
	<div class="col-sm-10 col-xs-12">
		<div class="alert alert-info">
			<ol>
				<li>
					Create a <strong>Google Firebase Application</strong> via the
					<a href="https://firebase.google.com/docs/auth/">API Console</a> and then paste
					your application details here.
				</li>
				<li>Ensure you have your firebase project in your firebase console.</li>
				<li>The appropriate "Redirect URI" is your NodeBB's URL with `/auth/firebase/callback` appended to it.</li>
			</ol>
		</div>
		<form role="form" class="sso-firebase-settings">
			<div class="form-group">
				<label for="firebase-service-account">Firebase Service Account config file</label>
				<input type="text" name="firebase-service-account" title="Firebase Service Account config file" class="form-control input-lg" placeholder="Firebase Service Account config file">
			</div>
			<div class="form-group">
				<label for="firebase-database-url">Firebase database url</label>
				<input type="text" name="firebase-database-url" title="Firebase database url" class="form-control" placeholder="Firebase database url">
			</div>
			<div class="form-group">
				<label for="firebase-project-id">Firebase Project Id</label>
				<input type="text" name="firebase-project-id" title="Firebase Project Id" class="form-control" placeholder="Firebase Project Id">
			</div>
			<div class="form-group">
				<label for="authorizationurl">SSO Server Url</label>
				<input type="text" name="authorizationurl" title="SSO Server Url" class="form-control" placeholder="SSO Server Url">
			</div>
			<div class="checkbox">
				<label class="mdl-switch mdl-js-switch mdl-js-ripple-effect">
					<input type="checkbox" class="mdl-switch__input" name="usingState">
					<span class="mdl-switch__label">Using State parameter (Prevent CSRF attack)</span>
				</label>
			</div>
			<div class="checkbox">
				<label class="mdl-switch mdl-js-switch mdl-js-ripple-effect">
					<input type="checkbox" class="mdl-switch__input" name="autoconfirm">
					<span class="mdl-switch__label">Skip email verification for people who register using SSO?</span>
				</label>
			</div>
			<div class="checkbox">
				<label class="mdl-switch mdl-js-switch mdl-js-ripple-effect">
					<input type="checkbox" class="mdl-switch__input" name="allowFirebaseRegister">
					<span class="mdl-switch__label">Allow new user who register using SSO?</span>
				</label>
			</div>
			<div class="checkbox">
				<label class="mdl-switch mdl-js-switch mdl-js-ripple-effect">
					<input type="checkbox" class="mdl-switch__input" name="allowFirebaseLogin">
					<span class="mdl-switch__label">Allow Firebase SSO login</span>
				</label>
			</div>
		</form>
	</div>
</div>

<button id="save" class="floating-button mdl-button mdl-js-button mdl-button--fab mdl-js-ripple-effect mdl-button--colored">
	<i class="material-icons">save</i>
</button>
