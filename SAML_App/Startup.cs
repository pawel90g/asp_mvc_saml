using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace SAML_App
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddRazorPages();

            services.Configure<Saml2Configuration>(Configuration.GetSection("Saml2"));

            services.Configure<Saml2Configuration>(saml2Configuration =>
            {
                saml2Configuration.AllowedAudienceUris.Add(saml2Configuration.Issuer);

                var entityDescriptor = new EntityDescriptor();
                entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(Configuration["Saml2:IdPMetadata"]));
                if (entityDescriptor.IdPSsoDescriptor != null)
                {
                    saml2Configuration.SingleSignOnDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
                    saml2Configuration.SignatureValidationCertificates.AddRange(entityDescriptor.IdPSsoDescriptor.SigningCertificates);
                }
                else
                {
                    throw new Exception("IdPSsoDescriptor not loaded from metadata.");
                }
            });

            services.AddSaml2();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            //if (env.IsDevelopment())
            //{
                app.UseDeveloperExceptionPage();
            //}
            //else
            //{
            //    app.UseExceptionHandler("/Error");
            //    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            //    app.UseHsts();
            //}

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();

                endpoints.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");
            });

            app.UseSaml2();
        }
    }
}
