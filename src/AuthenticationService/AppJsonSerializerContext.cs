using System.Text.Json.Serialization;
using Auriga.Toolkit.AspNetCore.Authentication.Abstractions.Models;

[JsonSerializable(typeof(AuthResponseModel))]
[JsonSerializable(typeof(string))]
internal sealed partial class AppJsonSerializerContext : JsonSerializerContext;
