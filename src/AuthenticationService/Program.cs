using Auriga.Toolkit.AspNetCore.Extensions;
using Microsoft.IdentityModel.Logging;

WebApplication app = WebApplication.CreateSlimBuilder(args)
	.BuildApplication();

IdentityModelEventSource.ShowPII = true;

app.Run();
