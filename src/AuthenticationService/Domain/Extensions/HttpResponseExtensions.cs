using Auriga.Servicekit.AuthenticationService.Domain.Models;
using Auriga.Toolkit.AspNetCore.Authentication;
using Auriga.Toolkit.Authentication.OpenIdConnect;
using Auriga.Toolkit.Http;

namespace Auriga.Servicekit.AuthenticationService.Domain.Extensions;

internal static class HttpResponseExtensions
{
	/// <summary>
	/// Parses result from auth provider, then prepare: <br/>
	/// - Refresh token explicitly set in HTTP-only cookies.<br/>
	/// - Auth token split into header and HTTP-only cookies.
	/// </summary>
	/// <param name="response">Auth provider response.</param>
	/// <param name="config">Application configuration.</param>
	/// <param name="receivedToken">Token, received from auth provider.</param>
	/// <returns>Partial payload for client.</returns>
	internal static IResult HandleReceivedToken(
		this HttpResponse response,
		AuthenticationFeatureOptions config,
		OpenIdConnectTokenResponseModel receivedToken)
	{
		// Here we gonna prepare our divided secret
		var jwtAccessToken = JwtTokenStructureModel.Parse(receivedToken.AccessToken);
		// Header and payload will be inside cookies, Payload will be sent back to client
		string tokenPart = $"{jwtAccessToken.Header}.{jwtAccessToken.Payload}";

		// Auth token usage Limited for paths
		UpdateCookies(response, CookieName.AuthToken, tokenPart, config.CookiePolicy.RestrictionPaths, TimeSpan.FromSeconds(receivedToken.AccessTokenExpiresIn));
		UpdateCookies(response, CookieName.RefreshToken, receivedToken.RefreshToken, config.CookiePolicy.RestrictionPaths, TimeSpan.FromSeconds(receivedToken.RefreshTokenExpiresIn));

		return Results.Ok(new AuthResponseModel
		{
			Access = jwtAccessToken.Signature,
			ExpiresIn = receivedToken.AccessTokenExpiresIn,
			LoggedAt = DateTime.UtcNow,
			TokenType = receivedToken.TokenType,
			SessionId = receivedToken.SessionId
		});
	}

	public static void UpdateCookies(this HttpResponse response, string cookieName, string token, IReadOnlyDictionary<string, string>? cookieRestrictionSettings, TimeSpan tokenTimeout)
	{
		if (cookieRestrictionSettings == null)
		{
			///Log something
			return;
		}

		if (!cookieRestrictionSettings.TryGetValue(cookieName, out string? cookieRestriction))
		{
			///Log something
			return;
		}

		response.Cookies.Append(
			cookieName,
			token,
			new()
			{
				Domain = null,
				MaxAge = tokenTimeout,
				Path = $"{cookieRestriction}"
			});
	}

	public static void DeleteCookies(this HttpResponse response, IReadOnlyDictionary<string, string>? cookieRestrictionSettings)
	{
		if (cookieRestrictionSettings == null)
		{
			///Log something
			return;
		}

		foreach (KeyValuePair<string, string> cookieRestriction in cookieRestrictionSettings)
		{
			response.Cookies.Append(
				cookieRestriction.Key,
				string.Empty,
				new()
				{
					Domain = null,
					MaxAge = TimeSpan.Zero,
					Path = $"{cookieRestriction.Value}"
				});
		}
	}
}
