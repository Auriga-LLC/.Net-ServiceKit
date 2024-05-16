using System.Diagnostics.CodeAnalysis;
using Newtonsoft.Json;

namespace Auriga.Servicekit.AuthenticationService.Domain.Models;

/// <summary>
/// Auth provider realm model.
/// </summary>
[ExcludeFromCodeCoverage]
public sealed record RealmModel
{
	/// <summary>
	/// Gets or sets realm id.
	/// </summary>
	[JsonProperty("id")]
	public Guid Id { get; set; }
}
