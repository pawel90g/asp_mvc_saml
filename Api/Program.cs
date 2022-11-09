using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

var app = builder.Build();

app.MapGet("/api", () => new[] { "value1", "value2", "value3" });

app.Run();