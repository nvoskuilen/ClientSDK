using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace ExactOnline.Client.OAuth
{
    public class AutoLogin
    {
        public static async Task<Uri> LoginToExactOnlineAsync(Uri uri, string username, string password)
        {
            using (var httpClient = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, AutomaticDecompression = DecompressionMethods.Deflate | DecompressionMethods.GZip }, disposeHandler: true))
            {
                httpClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "DotNetOpenAuth.Core/4.3.4.13329");

                // Touch ExactOnline
                var responseContent = await httpClient.GetStringAsync(uri).ConfigureAwait(false);

                // Extract the tokens from the response, and add the login credentials
                var tokens = await ParseTokensAsync(responseContent).ConfigureAwait(false);
                tokens.Add("UserNameField", username);
                tokens.Add("PasswordField", password);
                tokens.Add("LoginButton", "Login");

                // Post the data to ExactOnline, and return the authorizationUri
                using (var postData = new FormUrlEncodedContent(tokens))
                {
                    using (var response = await httpClient.PostAsync(uri, postData).ConfigureAwait(false))
                    {
                        if (!response.StatusCode.Equals(HttpStatusCode.Redirect))
                        {
                            throw new Exception("Failed to login to ExactOnline.");
                        }

                        return response.Headers.Location;
                    }
                }
            }
        }

        private static async Task<Dictionary<string, string>> ParseTokensAsync(string responseContent)
        {
            // A 'not so nice' html parser...

            var dict = new Dictionary<string, string>();

            const string s1 = "<input type=\"hidden\"";
            const string s2 = "\"";
            const StringComparison stringComparer = StringComparison.OrdinalIgnoreCase;

            using (var stringReader = new StringReader(responseContent))
            {
                while (stringReader.Peek() >= 0)
                {
                    var content = await stringReader.ReadLineAsync().ConfigureAwait(false);

                    if (!content.Contains(s1))
                    {
                        continue;
                    }

                    const string idP1 = "id=\"";
                    var idP2 = content.Substring(content.IndexOf(idP1, stringComparer) + idP1.Length);
                    var id = idP2.Substring(0, idP2.IndexOf(s2, stringComparer));

                    const string valueP1 = "value=\"";
                    var valueP2 = content.Substring(content.IndexOf(valueP1, stringComparer) + valueP1.Length);
                    var value = valueP2.Substring(0, valueP2.IndexOf(s2, stringComparer));

                    dict.Add(id, value);
                }
            }

            return dict;
        }
    }
}
