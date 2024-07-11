using System.Text.Json.Serialization;
using Auriga.Servicekit.AuthenticationService.Domain.Models;

[JsonSerializable(typeof(AuthResponseModel))]
[JsonSerializable(typeof(string))]
internal sealed partial class AppJsonSerializerContext : JsonSerializerContext;
