using DotNetOpenAuth.OAuth2;
using System;

namespace ExactOnline.Client.OAuth
{
	public static class UserAuthorizations
	{
		private static AuthorizationServerDescription _serverDescription;

		public static void Authorize(UserAuthorization authorization, string website, string clientId, string clientSecret, Uri redirectUri)
		{

			if (_serverDescription == null)
			{
				_serverDescription = new AuthorizationServerDescription
				{
					AuthorizationEndpoint = new Uri(string.Format("{0}/api/oauth2/auth", website)),
					TokenEndpoint = new Uri(string.Format("{0}/api/oauth2/token", website))
				};
			}
			var oAuthClient = new OAuthClient(_serverDescription, clientId, clientSecret, redirectUri);

			var authorizationState = authorization.AuthorizationState;
			oAuthClient.Authorize(ref authorizationState, authorization.RefreshToken);
			authorization.AuthorizationState = authorizationState;
		}
	}
}