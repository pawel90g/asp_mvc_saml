using System;
using System.Linq;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using SAML_App;
using SAML_App.Options;
using SAML_App.Store;

var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;

services.AddRazorPages();

services.AddMemoryCache();

services.Configure<RedisCacheOptions>(builder.Configuration.GetSection("RedisCache"));

// services.AddSingleton<ITicketStore, MemoryCacheTicketStore>();
services.AddSingleton<IBackedupTicketStore, RedisCacheTicketStore>();

services.AddHostedService<RedisNotificationsHandler>();

services.Configure<Saml2Configuration>(builder.Configuration.GetSection("Saml2"));

services.Configure<Saml2Configuration>(saml2Configuration =>
{
    saml2Configuration.AllowedAudienceUris.Add(saml2Configuration.Issuer);

    var entityDescriptor = new EntityDescriptor();
    entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(builder.Configuration["Saml2:IdPMetadata"]));
    if (entityDescriptor.IdPSsoDescriptor != null)
    {
        saml2Configuration.SingleSignOnDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
        saml2Configuration.SingleLogoutDestination = entityDescriptor.IdPSsoDescriptor.SingleLogoutServices.First().Location;
        saml2Configuration.SignatureValidationCertificates.AddRange(entityDescriptor.IdPSsoDescriptor.SigningCertificates);
    }
    else
    {
        throw new Exception("IdPSsoDescriptor not loaded from metadata.");
    }
});

var ticketStore = services.BuildServiceProvider().GetService<IBackedupTicketStore>();

services.AddSaml2(sessionStore: ticketStore);

var app = builder.Build();

app.UseDeveloperExceptionPage();

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseSaml2();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapRazorPages();

    endpoints.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
});

app.UseSaml2();

app.Run();