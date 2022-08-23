using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Claims;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SAML_App.Identity;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Authentication;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SAML_App.Controllers
{
    [AllowAnonymous]
    [Route("Auth")]
    public class AuthController : Controller
    {
        const string relayStateReturnUrl = "ReturnUrl";

        private readonly Saml2Configuration config;
        private readonly ITicketStore ticketStore;

        public AuthController(IOptions<Saml2Configuration> configAccessor,
            ITicketStore ticketStore)
        {
            config = configAccessor.Value;
            this.ticketStore = ticketStore;
        }

        [Route("Login")]
        public IActionResult Login(string returnUrl = null)
        {
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl ?? Url.Content("~/") } });

            return binding.Bind(new Saml2AuthnRequest(config)).ToActionResult();
        }

        [Route("AssertionConsumerService")]
        public async Task<IActionResult> AssertionConsumerService()
        {
            var binding = new Saml2PostBinding();

            var saml2AuthnResponse = new Saml2AuthnResponse(config);

            binding.ReadSamlResponse(Request.ToGenericHttpRequest(), saml2AuthnResponse);

            if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
                throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");

            binding.Unbind(Request.ToGenericHttpRequest(), saml2AuthnResponse);

            await saml2AuthnResponse.CreateSession(
                HttpContext,
                claimsTransform: (claimsPrincipal) =>
                    ClaimsTransform.Transform(claimsPrincipal));

            var relayStateQuery = binding.GetRelayStateQuery();
            var returnUrl = relayStateQuery.ContainsKey(relayStateReturnUrl)
                ? relayStateQuery[relayStateReturnUrl]
                : Url.Content("~/");

            return Redirect(returnUrl);
        }

        [HttpPost("Logout")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return Redirect(Url.Content("~/"));
            }

            var binding = new Saml2PostBinding();
            var saml2LogoutRequest = await new Saml2LogoutRequest(config, User).DeleteSession(HttpContext);
            return Redirect("~/");
        }

        [Route("LoggedOut")]
        public IActionResult LoggedOut()
        {
            var binding = new Saml2PostBinding();
            binding.Unbind(Request.ToGenericHttpRequest(), new Saml2LogoutResponse(config));

            return Redirect(Url.Content("~/"));
        }

        [Route("SingleLogout")]
        public async Task<IActionResult> SingleLogout()
        {
            Saml2StatusCodes status;
            var requestBinding = new Saml2RedirectBinding();
            var logoutRequest = new Saml2LogoutRequest(config, User);
            try
            {
                requestBinding.Unbind(Request.ToGenericHttpRequest(), logoutRequest);
                status = Saml2StatusCodes.Success;

                await ticketStore.RemoveAsync(logoutRequest.SessionIndex);

                //HttpContext.User = Saml2LogoutRequestToClaimsPrincipal(logoutRequest);

                await logoutRequest.DeleteSession(HttpContext);
            }
            catch (Exception exc)
            {
                // log exception
                Debug.WriteLine("SingleLogout error: " + exc.ToString());
                status = Saml2StatusCodes.RequestDenied;
            }

            var responsebinding = new Saml2PostBinding();
            responsebinding.RelayState = requestBinding.RelayState;
            var saml2LogoutResponse = new Saml2LogoutResponse(config)
            {
                InResponseToAsString = logoutRequest.IdAsString,
                Status = status,
            };

            return responsebinding.Bind(saml2LogoutResponse).ToActionResult();
        }

        private ClaimsPrincipal Saml2LogoutRequestToClaimsPrincipal(Saml2LogoutRequest logoutRequest) =>
             new ClaimsPrincipal(
                new ClaimsIdentity(
                    claims: new List<Claim> {
                        new Claim(ClaimTypes.NameIdentifier, logoutRequest.NameId.Value),
                        new Claim(ClaimTypes.Email, logoutRequest.NameId.Value),
                        new Claim(ClaimTypes.Name, logoutRequest.NameId.Value),
                        new Claim(Saml2ClaimTypes.NameIdFormat, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
                        new Claim(Saml2ClaimTypes.NameId, logoutRequest.NameId.Value),
                        new Claim(Saml2ClaimTypes.SessionIndex, logoutRequest.SessionIndex),
                    },
                    authenticationType: Saml2Constants.AuthenticationScheme));
    }
}