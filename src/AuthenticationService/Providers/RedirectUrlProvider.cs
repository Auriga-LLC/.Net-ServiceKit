using System.Text.RegularExpressions;
using Auriga.Servicekit.AuthenticationService.Domain.Enums;
using Auriga.Toolkit.Configuration;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;

namespace Auriga.Servicekit.AuthenticationService.Providers;

internal sealed partial class RedirectUrlProvider(
	ILogger<RedirectUrlProvider> logger,
	IConfiguration configuration) : IRedirectUrlProvider
{
	[GeneratedRegex(@"^.*(?'url'https?://[\w-]+.+[\w-]+/[\w- ./?%&=]?).*$", RegexOptions.IgnoreCase, "en-US")]
	private static partial Regex UrlRegex();

	/// <inheritdoc/>
	public Uri? GetPostLoginUri(IHeaderDictionary requestHeaders, string state)
	{
		if (!requestHeaders.TryGetValue(HeaderNames.Referer, out StringValues referer))
		{
			logger.LogWarning("Missing header Referer");
		}

		referer = !string.IsNullOrWhiteSpace(referer) ? referer.ToString().Split('?')[0] : UrlRegex().Replace(state, "${url}", 1);
		logger.LogWarning("Referer:{0} in postLogin", referer);
		return new Uri(
			string.Concat(
				referer.ToString().AsSpan().TrimEnd('/'),
				"/".AsSpan(),
				RouteConstants.RequestToken.TrimStart('/').AsSpan()));
	}

	/// <inheritdoc/>
	public Uri? GetTokenIssuerUri(IHeaderDictionary requestHeaders, string state)
	{
		if (!requestHeaders.TryGetValue(HeaderNames.Referer, out StringValues referer))
		{
			logger.LogWarning("Missing header Referer");
		}

		referer = !string.IsNullOrWhiteSpace(referer) ? referer : configuration.GetConfiguration<string>("Application:PublicEndpoint");
		logger.LogWarning("Referer in token:{0}", referer);
		return new Uri(
			string.Concat(
				referer.ToString().AsSpan().TrimEnd('/'),
				"/".AsSpan(),
				RouteConstants.RequestToken.TrimStart('/').AsSpan()));
	}

	/// <inheritdoc/>
	public Uri? GetPostLogoutUrl(IHeaderDictionary requestHeaders, Uri? redirectUrl)
	{
		if (!requestHeaders.TryGetValue(HeaderNames.Referer, out StringValues referer) || string.IsNullOrWhiteSpace(referer))
		{
			throw new InvalidOperationException("Referer");
		}

		return string.IsNullOrWhiteSpace(redirectUrl?.ToString())
			? new Uri(referer!)
			: new Uri(new Uri(referer!), redirectUrl);
	}
}
