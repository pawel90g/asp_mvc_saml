using System;
using System.Threading.Tasks;
using ITfoxtec.Identity.Saml2.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Redis;
using Microsoft.Extensions.Configuration;

namespace SAML_App.Store;

internal class RedisCacheTicketStore : IBackedupTicketStore
{
    private IDistributedCache _cache;

    public RedisCacheTicketStore(IConfiguration configuration) =>
        _cache = new RedisCache(new RedisCacheOptions
        {
            Configuration = configuration["RedisCache:ConnStr"]
        });

    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var key = ticket.Principal.FindFirst(Saml2ClaimTypes.SessionIndex)?.Value
                    ?? Guid.NewGuid().ToString();
        await RenewAsync(key, ticket);
        return key;
    }

    public async Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        var options = new DistributedCacheEntryOptions();
        options.SetAbsoluteExpiration(new TimeSpan(0, 1, 0));

        // var expiresUtc = ticket.Properties.ExpiresUtc;
        // if (expiresUtc.HasValue)
        // {
        //     options.SetAbsoluteExpiration(expiresUtc.Value);
        // }

        byte[] val = SerializeToBytes(ticket);
        _cache.Set(key, val, options);

        await BackupAsync(key, ticket);
    }

    private Task BackupAsync(string key, AuthenticationTicket ticket)
    {
        var options = new DistributedCacheEntryOptions();
        options.SetAbsoluteExpiration(new TimeSpan(0, 1, 30));

        // var expiresUtc = ticket.Properties.ExpiresUtc;
        // if (expiresUtc.HasValue)
        // {
        //     options.SetAbsoluteExpiration(expiresUtc.Value);
        // }

        byte[] val = SerializeToBytes(ticket);
        _cache.Set($"{key}_bak", val, options);

        return Task.FromResult(0);
    }

    public Task<AuthenticationTicket> RetrieveAsync(string key)
    {
        byte[] bytes = null;
        bytes = _cache.Get(key);
        var ticket = DeserializeFromBytes(bytes);
        return Task.FromResult(ticket);
    }

    public Task<AuthenticationTicket> RetrieveFromBackupAsync(string key)
    {
        byte[] bytes = null;
        bytes = _cache.Get($"{key}_bak");
        var ticket = DeserializeFromBytes(bytes);
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