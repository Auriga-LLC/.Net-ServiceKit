using System.Diagnostics.CodeAnalysis;
using Newtonsoft.Json;

namespace Auriga.Servicekit.AuthenticationService.Domain.Models;

/// <summary>
/// Auth response model.
/// </summary>
[ExcludeFromCodeCoverage]
[Serializable]
public sealed record AuthResponseModel
{
	/// <summary>
	/// Public part of auth token.
	/// </summary>
	[JsonProperty("access")]
	public string Access { get; set; } = string.Empty;

	/// <summary>
	/// Auth token expiration timer.
	/// </summary>
	[JsonProperty("expiresIn")]
	public int ExpiresIn { get; init; }

	/// <summary>
	/// Token issue time.
	/// </summary>
	[JsonProperty("loggedAt")]
	public DateTime LoggedAt { get; init; } = DateTime.UtcNow;

	/// <summary>
	/// Issued token type.
	/// </summary>
	[JsonProperty("type")]
	public string TokenType { get; init; } = string.Empty;

	/// <summary>
	/// Current session Id.
	/// </summary>
	[JsonProperty("sessionId")]
	public Guid SessionId { get; init; }
}
