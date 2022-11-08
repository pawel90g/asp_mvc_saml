using ITfoxtec.Identity.Saml2.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Caching.Memory;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SAML_App.Store
{
    public class MemoryCacheTicketStore : ITicketStore
    {
        private static readonly Dictionary<string, object> cache = new Dictionary<string, object>();

        public MemoryCacheTicketStore() { }

        public Task RemoveAsync(string key)
        {
            cache.Remove(key);
            return Task.FromResult(0);
        }

        public Task RenewAsync(string key, AuthenticationTicket ticket)
        {
            var options = new MemoryCacheEntryOptions
            {
                Priority = CacheItemPriority.NeverRemove
            };
            var expiresUtc = ticket.Properties.ExpiresUtc;

            if (expiresUtc.HasValue)
            {
                options.SetAbsoluteExpiration(expiresUtc.Value);
            }

            options.SetSlidingExpiration(TimeSpan.FromMinutes(60));

            cache.Add(key, ticket);
            //cache.Set(key, ticket, options);

            return Task.FromResult(0);
        }

        public Task<AuthenticationTicket> RetrieveAsync(string key)
        {
            var ticket = cache.ContainsKey(key)
                ? (AuthenticationTicket)cache[key]
                : null;
            //cache.TryGetValue(key, out AuthenticationTicket ticket);
            return Task.FromResult(ticket);
        }

        public async Task<string> StoreAsync(AuthenticationTicket ticket)
        {
            var key = ticket.Principal.FindFirst(Saml2ClaimTypes.SessionIndex)?.Value
                ?? Guid.NewGuid().ToString();
            await RenewAsync(key, ticket);
            return key;
        }
    }
}
