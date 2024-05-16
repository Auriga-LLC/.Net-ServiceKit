using Auriga.Servicekit.AuthenticationService.Controllers;

namespace Auriga.Servicekit.AuthenticationService.Extensions;

internal static class RouteGroupBuilderExtensions
{
	public static RouteGroupBuilder MapAuthenticationApi(this RouteGroupBuilder routeGroup)
	{
		_ = routeGroup.MapGet(RouteConstants.RedirectToLogin, AuthenticationController.RedirectToLogin);
		_ = routeGroup.MapPost(RouteConstants.LoginByCredentials, AuthenticationController.LoginByCredentialsAsync);
		_ = routeGroup.MapGet(RouteConstants.RequestToken, AuthenticationController.RequestTokenAsync);
		_ = routeGroup.MapGet(RouteConstants.RefreshToken, AuthenticationController.RefreshTokenAsync);
		_ = routeGroup.MapPost(RouteConstants.RefreshToken, AuthenticationController.RefreshTokenAsync);
		_ = routeGroup.MapGet(RouteConstants.Logout, AuthenticationController.LogoutAsync);
		_ = routeGroup.MapPost(RouteConstants.RevokeTokens, AuthenticationController.RevokeTokensAsync);
		_ = routeGroup.MapGet(RouteConstants.WhoAmI, AuthenticationController.WhoAmIAsync);

		return routeGroup;
	}
}
