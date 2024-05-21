namespace Auriga.Servicekit.AuthenticationService.Providers;

internal interface IRedirectUrlProvider
{
	/// <summary>
	/// Gets UI redirect URL for handling authentication phases.
	/// </summary>
	/// <param name="requestHeaders">Current <see cref="HttpRequest.Headers"/>.</param>
	/// <param name="state">Current flow state.</param>
	/// <returns>UI redirect URL.</returns>
	Uri? GetTokenIssuerUri(IHeaderDictionary requestHeaders, string state);

	Uri? GetPostLoginUri(IHeaderDictionary requestHeaders, string state);

	Uri? GetPostLogoutUrl(IHeaderDictionary requestHeaders, Uri? redirectUrl);
}
