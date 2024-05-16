using Keycloak.Plugin.Abstractions.Models;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Auriga.Toolkit.AspNetCore.Authentication.Abstractions;
using Auriga.Toolkit.AspNetCore.Authentication.Abstractions.Configuration;
using Auriga.Toolkit.Authentication.OpenIdConnect;
using Auriga.Toolkit.Authentication.OpenIdConnect.Keycloak;
using Auriga.Toolkit.Authentication.OpenIdConnect.Keycloak.Models;
using Auriga.Servicekit.AuthenticationService.Domain.Extensions;
using Auriga.Toolkit.Http.Abstractions.Enums;
using Auriga.Toolkit.Logging.Abstractions;
using Auriga.Toolkit.Runtime.Abstractions;

namespace Auriga.Servicekit.AuthenticationService.Controllers;

internal sealed class AuthenticationController
{
	/// <summary>
	/// Redirects client to auth provider login page.
	/// </summary>
	/// <param name="logger">Logger service.</param>
	/// <param name="provider">AuthProvider service client.</param>
	/// <param name="context">Current HTTP context.</param>
	/// <param name="state">Optional UI state.</param>
	/// <returns>Redirect result to be handled by browser.</returns>
	internal static async ValueTask<IResult> RedirectToLogin(
		ILogger<AuthenticationController> logger,
		IOpenIdConnectAuthenticationService provider,
		HttpContext context,
		[FromQuery] string state)
	{
		// Return back url for UI
		Uri? redirectUri = context.Request.GetAuthenticationHandlerUri();
		if (redirectUri == null)
		{
			return Results.BadRequest(nameof(redirectUri));
		}

		Operation<string> result = await provider.GetLoginPageUrlAsync(redirectUri, state);
		if (result.Result == null)
		{
			logger.LogMethodFailedWithErrors(nameof(provider.GetLoginPageUrlAsync), result.Errors);
			return Results.BadRequest(result.Errors);
		}

		return result.IsSucceed
			? Results.Redirect(result.Result, false, true)
			: Results.BadRequest(result.Errors);
	}

	/// <summary>
	/// Executes Login-by-credentials procedure.
	/// </summary>
	/// <param name="logger">Logger service.</param>
	/// <param name="config">App configuration options.</param>
	/// <param name="provider">AuthProvider service client.</param>
	/// <param name="context">Current HTTP context.</param>
	/// <param name="userId"></param>
	/// <param name="userSecret"></param>
	/// <returns>Splitted token secret.</returns>
	internal static async Task<IResult> LoginByCredentialsAsync(
		ILogger<AuthenticationController> logger,
		IOptions<AuthenticationFeatureOptions> config,
		IOpenIdConnectAuthenticationService provider,
		HttpContext context,
		[FromHeader(Name = HeaderName.UserId)] string userId,
		[FromHeader(Name = HeaderName.UserSecret)] string userSecret)
	{
		if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(userSecret))
		{
			return Results.Unauthorized();
		}

		Operation<OpenIdConnectTokenResponseModel?> tokenRequestOperation = await provider.ExchangeUserPasswordForTokenAsync(userId, userSecret, context.RequestAborted);
		if (tokenRequestOperation.Result == null)
		{
			logger.LogMethodFailedWithErrors(nameof(provider.ExchangeUserPasswordForTokenAsync), tokenRequestOperation.Errors);
			return Results.BadRequest(tokenRequestOperation.Errors);
		}

		if (tokenRequestOperation.IsSucceed)
		{
			return context.Response.HandleReceivedToken(config.Value, tokenRequestOperation.Result);
		}

		logger.LogMethodFailedWithErrors(nameof(LoginByCredentialsAsync), tokenRequestOperation.Errors);

		return Results.StatusCode(StatusCodes.Status500InternalServerError);
	}

	/// <summary>
	/// Initiates token request to auth provider. Received token will be returned as HTTP-only cookie.
	/// </summary>
	/// <param name="logger">Logger service.</param>
	/// <param name="config">App configuration options.</param>
	/// <param name="provider">AuthProvider service client.</param>
	/// <param name="context">Current HTTP context.</param>
	/// <param name="code">One-time password for getting token from provider.</param>
	/// <returns>Splitted token secret.</returns>
	internal static async Task<IResult> RequestTokenAsync(
		ILogger<AuthenticationController> logger,
		IOptions<AuthenticationFeatureOptions> config,
		IOpenIdConnectAuthenticationService provider,
		HttpContext context,
		[FromQuery] string code)
	{
		if (string.IsNullOrWhiteSpace(code))
		{
			return Results.BadRequest(nameof(code));
		}

		// Return back url for UI
		Uri? redirectUri = context.Request.GetAuthenticationHandlerUri();
		if (redirectUri == null)
		{
			return Results.BadRequest(nameof(redirectUri));
		}

		Operation<OpenIdConnectTokenResponseModel?> tokenExchangeOperation = await provider.ExchangeCodeForTokenAsync(redirectUri, code, context.RequestAborted);
		if (tokenExchangeOperation.Result == null)
		{
			logger.LogMethodFailedWithErrors(nameof(provider.ExchangeCodeForTokenAsync), tokenExchangeOperation.Errors);
			return Results.BadRequest(tokenExchangeOperation.Errors);
		}

		if (tokenExchangeOperation.IsSucceed)
		{
			return context.Response.HandleReceivedToken(config.Value, tokenExchangeOperation.Result);
		}

		logger.LogMethodFailedWithErrors(nameof(RequestTokenAsync), tokenExchangeOperation.Errors);

		return Results.StatusCode(StatusCodes.Status500InternalServerError);
	}

	/// <summary>
	/// Executes refresh token procedure.
	/// </summary>
	/// <param name="logger">Logger service.</param>
	/// <param name="config">App configuration options.</param>
	/// <param name="provider">AuthProvider service client.</param>
	/// <param name="context">Current HTTP context.</param>
	/// <param name="userSplitSecret">Users secret.</param>
	/// <returns>Splitted token secret.</returns>
	internal static async Task<IResult> RefreshTokenAsync(
		ILogger<AuthenticationController> logger,
		IOptions<AuthenticationFeatureOptions> config,
		IOpenIdConnectAuthenticationService provider,
		HttpContext context,
		SplitSecret userSplitSecret)
	{
		if (string.IsNullOrWhiteSpace(userSplitSecret.RefreshToken))
		{
			return Results.Unauthorized();
		}

		Operation<OpenIdConnectTokenResponseModel?> tokenRefreshOperation = await provider.ExchangeRefreshTokenAsync(userSplitSecret.RefreshToken, context.RequestAborted);
		if (tokenRefreshOperation.Result == null)
		{
			logger.LogMethodFailedWithErrors(nameof(provider.ExchangeRefreshTokenAsync), tokenRefreshOperation.Errors);
			return Results.BadRequest(tokenRefreshOperation.Errors);
		}

		if (tokenRefreshOperation.IsSucceed)
		{
			return context.Response.HandleReceivedToken(config.Value, tokenRefreshOperation.Result);
		}

		logger.LogMethodFailedWithErrors(nameof(RefreshTokenAsync), tokenRefreshOperation.Errors);

		return Results.StatusCode(StatusCodes.Status500InternalServerError);
	}

	/// <summary>
	/// Executes Logout procedure.
	/// </summary>
	/// <param name="logger">Logger service.</param>
	/// <param name="config">App configuration options.</param>
	/// <param name="provider">AuthProvider service client.</param>
	/// <param name="context">Current HTTP context.</param>
	/// <param name="userSplitSecret">Users secret.</param>
	/// <param name="redirectUri">Return back url for UI.</param>
	/// <param name="state">Optional UI state.</param>
	/// <returns>Redirect Url after Logout.</returns>
	internal static async Task<IResult> LogoutAsync(
		ILogger<AuthenticationController> logger,
		IOptions<AuthenticationFeatureOptions> config,
		IOpenIdConnectAuthenticationService provider,
		HttpContext context,
		SplitSecret userSplitSecret,
		[FromQuery(Name = "redirect_uri")] Uri? redirectUri,
		[FromQuery] string? state)
	{
		if (string.IsNullOrWhiteSpace(userSplitSecret.RefreshToken))
		{
			return Results.BadRequest(nameof(userSplitSecret.RefreshToken));
		}

		if (string.IsNullOrWhiteSpace(redirectUri?.ToString()))
		{
			return Results.BadRequest(nameof(redirectUri));
		}

		if (string.IsNullOrWhiteSpace(state))
		{
			return Results.BadRequest(nameof(state));
		}

		Operation result = await provider.LogoutAsync(userSplitSecret.RefreshToken, redirectUri, state, context.RequestAborted);
		if (result.IsSucceed)
		{
			context.Response.Headers.Location = context.Request.GetRedirectUrl(redirectUri).AbsoluteUri;
			context.Response.DeleteCookies(config.Value.CookiePolicy.RestrictionPaths);
			return Results.NoContent();
		}

		logger.LogMethodFailedWithErrors(nameof(LogoutAsync), result.Errors);

		return Results.StatusCode(StatusCodes.Status500InternalServerError);
	}

	/// <summary>
	/// Revoke all login sessions.
	/// </summary>
	/// <param name="logger">Logger service.</param>
	/// <param name="config">App configuration options.</param>
	/// <param name="provider">AuthProvider service client.</param>
	/// <param name="context">Current HTTP context.</param>
	/// <param name="userSplitSecret">Users secret.</param>
	/// <param name="redirectUri">Return back url for UI.</param>
	/// <returns>Redirect Url after logout.</returns>
	internal static async Task<IResult> RevokeTokensAsync(
		ILogger<AuthenticationController> logger,
		IOptions<AuthenticationFeatureOptions> config,
		IOpenIdConnectAuthenticationService provider,
		HttpContext context,
		SplitSecret userSplitSecret,
		[FromQuery(Name = "redirect_uri")] Uri? redirectUri)
	{
		if (string.IsNullOrWhiteSpace(userSplitSecret.RefreshToken))
		{
			return Results.BadRequest(nameof(userSplitSecret.RefreshToken));
		}

		Operation result = await provider.RevokeClientSessionAsync(userSplitSecret.RefreshToken, context.RequestAborted);
		if (result.IsSucceed)
		{
			context.Response.Headers.Location = context.Request.GetRedirectUrl(redirectUri).AbsoluteUri;
			context.Response.DeleteCookies(config.Value.CookiePolicy.RestrictionPaths);
			return Results.NoContent();
		}

		logger.LogMethodFailedWithErrors(nameof(RevokeTokensAsync), result.Errors);

		return Results.StatusCode(StatusCodes.Status500InternalServerError);
	}

	/// <summary>
	/// Get user info from auth provider.
	/// </summary>
	/// <param name="provider">AuthProvider service client.</param>
	/// <param name="context">Current HTTP context.</param>
	/// <param name="userSplitSecret">Users secret.</param>
	/// <returns>User info.</returns>
	internal static async Task<Results<UnauthorizedHttpResult, Ok<UserInfoResponseModel>, BadRequest<IEnumerable<string>>>> WhoAmIAsync(
		IKeycloakUsersServiceClient provider,
		HttpContext context,
		SplitSecret userSplitSecret)
	{
		Operation<UserInfoResponseModel?> result = await provider.GetUserInfoAsync(userSplitSecret.AuthenticationHeader, context.RequestAborted);
		return result.IsSucceed ?
			TypedResults.Ok(result.Result)
			: TypedResults.BadRequest(result.Errors);
	}
}
