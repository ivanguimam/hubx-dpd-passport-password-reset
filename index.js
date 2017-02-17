var AuthResource = require('../dpd-passport');
var uuid = require('deployd/lib/util/uuid');
var _handle = AuthResource.prototype.handle;
var sendGrid = require('sendgrid').mail;

AuthResource.events = AuthResource.events || [];
AuthResource.events.push("sendmail");

// add "allow passwort reset" as option to the dashboard
AuthResource.basicDashboard.settings.push({
  name        : 'allowPasswortReset',
  type        : 'checkbox',
  description : 'Allow users to reset their password'
});
AuthResource.basicDashboard.settings.push({
  name        : 'sendGridAPI',
  type        : 'text',
  description : 'API key SendGrid'
});
AuthResource.basicDashboard.settings.push({
  name        : 'siteUrl',
  type        : 'text',
  description : 'Site url, example: http://localhost:8081/alterar-senha'
});
AuthResource.basicDashboard.settings.push({
  name        : 'propertyMail',
  type        : 'text',
  description : "User's collection property wich corresponds to user email, i.e.: email"
});

AuthResource.prototype.initPasswortReset = function() {
  if(this.dpd) return;
  this.dpd = require('deployd/lib/internal-client').build(process.server, {isRoot: true}, []);
}

var sendResponse = function(ctx, err, res) {

  if(err) {
    ctx.res.statusCode = 401;
    return ctx.done('cannot reset password');
  } else {
    return ctx.done(err, res);
  }

}

AuthResource.prototype.handle = function (ctx, next) {

  if(ctx.method === 'POST' && ctx.url === '/forgot-password') {

    this.initPasswortReset();

		var self = this;
		var	dpd = this.dpd;

    var query = ctx.body;

    if(!query) {
      return sendResponse(ctx, true);
    }

    dpd[self.config.usersCollection].get(query, function(users, err) {

      if(!users || !users.length) {
        // we don't want to expose that a certain user is in our db (or not), so we just return success here.
        return ctx.done(null, 'You will receive instructions via email.');
      }

      var user = users[0];

      // set a resetToken
      var resetToken = uuid.create(64);

			dpd[self.config.usersCollection].put({
					id: user.id,
					resetToken: resetToken
				}).then(function(res){
					console.log(res);
					// send the mail
	        console.log('Send...', resetToken);

	        var from_email = new sendGrid.Email('devspgvn@gmail.com');
	        var to_email = new sendGrid.Email(user[self.config.propertyMail]);
	        var subject = 'Recuperação de senha';
	        var content = new sendGrid.Content('text/html', getHtmlMail(resetToken, self.config.siteUrl));
	        var mail = new sendGrid.Mail(from_email, subject, to_email, content);

	        var sg = require('sendgrid')(self.config.sendGridAPI);

					var request = sg.emptyRequest({
	          method: 'POST',
	          path: '/v3/mail/send',
	          body: mail.toJSON(),
	        });

	        sg.API(request, function(error, response) {
	          return ctx.done(response, error);
	        });

				}, function(error){
					return ctx.done(error);
				});

    });

  } else if(ctx.method === 'POST' && ctx.url === '/reset-password') {

    this.initPasswortReset();

		var self = this;
		var	dpd = this.dpd;
    var username = ctx.body.username;
    var password = ctx.body.password;
    var confirmation = ctx.body.confirmation;
    var token = ctx.body.token;

    if(!username || !password) {
      return sendResponse(ctx, true);
    }

    if(!(password===confirmation)) {
      ctx.res.statusCode = 401;
      return ctx.done('password must match confirmation');
    }

		dpd[self.config.usersCollection].get({
				$and: [
					{
						username: username
					},
					{
						resetToken: token
					}
				]
			}).then(function(users) {

				if(!users || !users.length) {
					return sendResponse(ctx, true);
				}

	      var user = users[0];

	      // delete the resetToken and update the password
	      dpd[self.config.usersCollection].put({id: user.id, password: password, resetToken: ''}, function(res, err) {
	        // end the request;
	        return ctx.done(err, 'The password was successfully updated!');
	      });

			}, function(err){
				return ctx.done(err);
			});

  } else {
    // handover to original module
    return _handle.apply(this, arguments);
  }

}

function getHtmlMail(token, url) {
  return '<p style="color: #f00; display: block; text-align: center;">Olá, clique no botão abaixo para alterar sua senha caso você tenha solicitado:</p>' +
  '<a href="' + url + '/' + token +'" style="background: rgba(60, 184, 120, 0.85); display: block; width: 120px; margin: 0 auto; text-align: center; color: #FFF; text-decoration: none; padding: 8px 0;">Alterar senha</a>' +
  '<p style="color: #f00; display: block; text-align: center;">Obs: caso você não tenha solicitado, apenas ignore este e-mail.</p>';
}
