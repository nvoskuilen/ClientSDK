using System;
using System.Windows.Forms;

namespace ExactOnline.Client.OAuth
{
	public partial class LoginForm : Form
	{
		private readonly Uri _redirectUri;

		#region Property

		public Uri AuthorizationUri { get; set; }

		#endregion

		#region Constructor

		public LoginForm(Uri redirectUri)
			: this()
		{
			_redirectUri = redirectUri;
		}

		public LoginForm()
		{
			InitializeComponent();
			WebBrowser.Navigated += WebBrowserNavigated;
		}

		#endregion

		private void LoginFormLoad(object sender, EventArgs e)
		{
			WebBrowser.Navigate(AuthorizationUri);
		}

		#region Events

		private void WebBrowserNavigated(object sender, WebBrowserNavigatedEventArgs e)
		{
			if (IsRedirected(e.Url))
			{
				AuthorizationUri = e.Url;
				Hide();
			}
		}

		#endregion

		#region Private Methods

		/// <summary>
		/// Tests whether two URLs are equal for purposes of detecting the conclusion of authorization.
		/// </summary>
		private bool IsRedirected(Uri uri)
		{
			var uriComponents = uri.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.Unescaped);
			var redirectUri = _redirectUri.ToString();
			if (uriComponents.EndsWith("/") && !redirectUri.EndsWith("/"))
			{
				redirectUri = redirectUri + "/";
			}

			return string.Equals(uriComponents, redirectUri, StringComparison.Ordinal);
		}

		#endregion
	}
}
