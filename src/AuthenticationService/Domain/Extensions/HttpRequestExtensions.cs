using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;

namespace Auriga.Servicekit.AuthenticationService.Domain.Extensions;

/// <summary>
/// HTTP request extensions class.
/// </summary>
internal static class HttpRequestExtensions
{
	/// <summary>
	/// Gets UI redirect URL for handling authentication phases.
	/// </summary>
	/// <param name="request">Current <see cref="HttpRequest"/>.</param>
	/// <returns>UI redirect URL.</returns>
	internal static Uri? GetAuthenticationHandlerUri(this HttpRequest request)
	{
		if (!request.Headers.TryGetValue(HeaderNames.Referer, out StringValues referer) || string.IsNullOrWhiteSpace(referer))
		{
			return null;
		}

		return new Uri(new Uri(referer!), RouteConstants.AuthControllerRoot + RouteConstants.RequestToken);
	}

	/// <summary>
	/// Get redirect Url for client while in OpenID flow.
	/// </summary>
	/// <param name="request">Current HttpRequest.</param>
	/// <param name="redirectUrl">Optional redirect Url.</param>
	/// <returns>Redirect info.</returns>
	public static Uri GetRedirectUrl(this HttpRequest request, Uri? redirectUrl)
	{
		if (!request.Headers.TryGetValue(HeaderNames.Referer, out StringValues referer) || string.IsNullOrWhiteSpace(referer))
		{
			throw new InvalidOperationException("Referer");
		}

		return string.IsNullOrWhiteSpace(redirectUrl?.ToString())
			? new Uri(referer!)
			: new Uri(new Uri(referer!), redirectUrl);
	}
}
