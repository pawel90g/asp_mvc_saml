using System;
using System.Threading.Tasks;
using ITfoxtec.Identity.Saml2.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Redis;
using Microsoft.Extensions.Configuration;

namespace SAML_App.Store;

internal class RedisCacheTicketStore : ITicketStore
{
    private IDistributedCache _cache;

    public RedisCacheTicketStore(IConfiguration configuration) =>
        _cache = new RedisCache(new RedisCacheOptions
        {
            Configuration = configuration["RedisCache:ConnectionString"]
        });

    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var key = ticket.Principal.FindFirst(Saml2ClaimTypes.SessionIndex)?.Value
                    ?? Guid.NewGuid().ToString();
        await RenewAsync(key, ticket);
        return key;
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        var options = new DistributedCacheEntryOptions();
        var expiresUtc = ticket.Properties.ExpiresUtc;
        if (expiresUtc.HasValue)
        {
            options.SetAbsoluteExpiration(expiresUtc.Value);
        }
        byte[] val = SerializeToBytes(ticket);
        _cache.Set(key, val, options);
        return Task.FromResult(0);
    }

    public Task<AuthenticationTicket> RetrieveAsync(string key)
    {
        AuthenticationTicket ticket;
        byte[] bytes = null;
        bytes = _cache.Get(key);
        ticket = DeserializeFromBytes(bytes);
        return Task.FromResult(ticket);
    }

    public Task RemoveAsync(string key)
    {
        _cache.Remove(key);
        return Task.FromResult(0);
    }

    private static byte[] SerializeToBytes(AuthenticationTicket source) =>
        TicketSerializer.Default.Serialize(source);

    private static AuthenticationTicket DeserializeFromBytes(byte[] source) =>
        source == null ? null : TicketSerializer.Default.Deserialize(source);
}