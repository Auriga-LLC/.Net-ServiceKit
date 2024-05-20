using Auriga.Servicekit.AuthenticationService.Extensions;
using Auriga.Toolkit.Clients.Http;
using Auriga.Toolkit.Plugins;

namespace Auriga.Servicekit.AuthenticationService.Plugins;

/// <summary>
/// Authentication serive setup plugin.
/// </summary>
internal sealed class AuthenticationServicePlugin : FeaturePlugin, IServiceConfiguratorPlugin, IRoutingConfiguratorPlugin
{
	/// <inheritdoc/>
	public override string Name => "AuthenticationService";

	/// <inheritdoc/>
	public override int LoadOrder => (int)PluginLoadOrder.ApplicationLevelPlugin;

	/// <inheritdoc/>
	public IServiceCollection ConfigureServices(IServiceCollection services, IConfiguration configuration)
	{
		return services
			.ConfigureHttpJsonOptions(options => options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default))
			.AddTransient<IUserPasswordExchangerService, UserPasswordExchangerService>();
	}

	/// <inheritdoc/>
	public IEndpointRouteBuilder ConfigureRouting(IEndpointRouteBuilder endpoints)
	{
		return endpoints.MapGroup(RouteConstants.AuthControllerRoot)
			.MapAuthenticationApi();
	}
}

internal class UserPasswordExchangerService : IUserPasswordExchangerService
{
	public ValueTask<(string scheme, string jwtToken)> ExchangeUserPasswordAsync(string user, string password, CancellationToken cancellationToken = default)
	{
		return ValueTask.FromResult(("scheme", "token"));
	}
}
