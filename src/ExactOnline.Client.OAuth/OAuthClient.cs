using System;
using DotNetOpenAuth.OAuth2;
using DotNetOpenAuth.Messaging;

namespace ExactOnline.Client.OAuth
{
	public class OAuthClient : UserAgentClient
	{
        private readonly string _username;
        private readonly string _password;
		private readonly Uri _redirectUri;

		#region Constructor

        public OAuthClient(AuthorizationServerDescription serverDescription, string clientId, string clientSecret, string username, string password, Uri redirectUri)
			: base(serverDescription, clientId, clientSecret)
		{
            _username = username;
            _password = password;
			_redirectUri = redirectUri;
			ClientCredentialApplicator = ClientCredentialApplicator.PostParameter(clientSecret);
		}

		#endregion

		#region Public methods

		public void Authorize(ref IAuthorizationState authorization, string refreshToken)
		{
			if ((authorization == null))
			{
				authorization = new AuthorizationState
				{
					Callback = _redirectUri,
					RefreshToken = refreshToken
				};
			}

			bool refreshFailed = false;
			if (AccessTokenHasToBeRefreshed(authorization))
			{
				try
				{
					refreshFailed = !RefreshAuthorization(authorization);
				}
				catch (ProtocolException)
				{
					//The refreshtoken is not valid anymore
				}
			}

			if (authorization.AccessToken == null || refreshFailed)
			{
                // If username and password are supplied via the 'Connector', we skip the Login screen and perform AutoLogin
                if (!(string.IsNullOrWhiteSpace(_username) || string.IsNullOrWhiteSpace(_password)))
                {
                    var authorizationUri = GetAuthorizationUri(authorization);
                    authorizationUri = AutoLogin.LoginToExactOnlineAsync(authorizationUri, _username, _password).Result; // should go Async all the way..
                    ProcessUserAuthorization(authorizationUri, authorization);
                }
                else
                {
                    using (var loginDialog = new LoginForm(_redirectUri))
                    {
                        loginDialog.AuthorizationUri = GetAuthorizationUri(authorization);
                        loginDialog.ShowDialog();
                        ProcessUserAuthorization(loginDialog.AuthorizationUri, authorization);
                    }
                }
			}
		}

		#endregion

		#region Private methods

		private static bool AccessTokenHasToBeRefreshed(IAuthorizationState authorization)
		{
			if (authorization.AccessToken == null && authorization.RefreshToken != null)
			{
				return true;
			}

			if (authorization.AccessTokenExpirationUtc != null)
			{
				TimeSpan timeToExpire = authorization.AccessTokenExpirationUtc.Value.Subtract(DateTime.UtcNow);
				return (timeToExpire.Minutes < 1);
			}
			return false;
		}

		private Uri GetAuthorizationUri(IAuthorizationState authorization)
		{
			var baseUri = RequestUserAuthorization(authorization);

			var authorizationUriBuilder = new UriBuilder(baseUri)
			{
				Query = baseUri.Query.Substring(1) + "&force_login=1"
			};

			return authorizationUriBuilder.Uri;
		}

		#endregion

	}

}