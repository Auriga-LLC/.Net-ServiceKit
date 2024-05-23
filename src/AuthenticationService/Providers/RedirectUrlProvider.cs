using System.Text.RegularExpressions;
using Auriga.Servicekit.AuthenticationService.Domain.Enums;
using Auriga.Toolkit.Configuration;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using UrlCombineLib;

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

		if(string.IsNullOrWhiteSpace(referer))
		{
			referer = UrlRegex().Replace(state, "${url}", 1);
		}

		return new Uri(referer!);
	}

	/// <inheritdoc/>
	public Uri? GetTokenIssuerUri(IHeaderDictionary requestHeaders, string state)
	{
		if (!requestHeaders.TryGetValue(HeaderNames.Referer, out StringValues referer))
		{
			logger.LogWarning("Missing header Referer");
		}

		if(string.IsNullOrWhiteSpace(referer))
		{
			referer = configuration.GetConfiguration<string>("Application:PublicEndpoint");
		}

		return new Uri(referer)
			.Combine(RouteConstants.AuthControllerRoot, RouteConstants.RequestToken);
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
