using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using SecurityProxy;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

builder.Services.AddMemoryCache();
builder.Services.AddSingleton<ITicketStore, RedisCacheTicketStore>();

var app = builder.Build();

app.UseMiddleware<SessionVerifierMiddleware>();

app.MapReverseProxy();
app.Run();