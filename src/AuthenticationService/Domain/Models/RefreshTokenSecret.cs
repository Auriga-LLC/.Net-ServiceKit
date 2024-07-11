using System.Reflection;
using Auriga.Toolkit.AspNetCore.Authentication;

namespace Auriga.Servicekit.AuthenticationService.Domain.Models;

/// <summary>
/// Represents refresh token users secret.
/// </summary>
/// <param name="RefreshToken">Refresh token body.</param>
public record RefreshTokenSecret(string RefreshToken)
	: IBindableFromHttpContext<RefreshTokenSecret>
{
	/// <summary>
	/// Binds <see cref="RefreshTokenSecret"/> from Http context.
	/// </summary>
	/// <param name="context">Current Http context</param>
	/// <param name="_">Parameter metadata.</param>
	/// <returns>Built <see cref="RefreshTokenSecret"/>.</returns>
	public static ValueTask<RefreshTokenSecret?> BindAsync(HttpContext context, ParameterInfo _)
	{
		ArgumentNullException.ThrowIfNull(context);

		IUserRefreshTokenProvider? refreshTokenProvider = context.RequestServices.GetService<IUserRefreshTokenProvider>();
		string? refreshToken = refreshTokenProvider?.GetRefreshToken(context.Request);
		if (string.IsNullOrWhiteSpace(refreshToken))
		{
			return ValueTask.FromResult<RefreshTokenSecret?>(null);
		}

		return ValueTask.FromResult<RefreshTokenSecret?>(new RefreshTokenSecret(refreshToken));
	}
}
