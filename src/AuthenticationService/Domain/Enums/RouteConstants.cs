namespace Auriga.Servicekit.AuthenticationService.Domain.Enums;

internal static class RouteConstants
{
	public const string AuthControllerRoot = "";
	public const string RedirectToLogin = "/start";
	public const string LoginByCredentials = "/login";
	public const string RequestToken = "/callback";
	public const string RefreshToken = "/refresh";
	public const string Logout = "/logout";
	public const string RevokeTokens = "/revoke";
	public const string WhoAmI = "/me";
}
