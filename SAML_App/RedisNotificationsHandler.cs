using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using SAML_App.Options;
using StackExchange.Redis;

namespace SAML_App;

internal sealed class RedisNotificationsHandler : IHostedService
{
    private const string EXPIRE_EVENT_NAME = "expire";
    private const string EXPIRED_EVENT_NAME = "expired";
    private const string DEL_EVENT_NAME = "del";

    private readonly Lazy<ConnectionMultiplexer> lazyConnection;
    private readonly Saml2Configuration saml2Config;
    private readonly IBackedupTicketStore ticketStore;

    public RedisNotificationsHandler(
        IOptions<Saml2Configuration> configAccessor,
        IOptions<RedisCacheOptions> opt,
        IBackedupTicketStore ticketStore)
    {
        lazyConnection = new Lazy<ConnectionMultiplexer>(() =>
            ConnectionMultiplexer.Connect(opt.Value.ConnStr));

        this.saml2Config = configAccessor.Value;
        this.ticketStore = ticketStore;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        var redisConn = GetConnection().GetDatabase();
        var subscriber = GetConnection().GetSubscriber();
        var db = 0;
        var notificationChannel = "__keyspace@" + db + "__:*";

        subscriber.Subscribe(notificationChannel, async (channel, notificationType) =>
        {
            if (notificationType.HasValue)
            {
                Console.WriteLine($"[{DateTime.UtcNow}] Redis event occurs: {notificationType.ToString()}");
                var key = GetKey(channel);

                if (key.EndsWith("_bak"))
                    return;

                switch (notificationType.ToString())
                {
                    case EXPIRE_EVENT_NAME:
                        Console.WriteLine($"[{DateTime.UtcNow}] Expiration Set for Key: {key}");
                        break;
                    case EXPIRED_EVENT_NAME:
                    case DEL_EVENT_NAME:
                        Console.WriteLine($"[{DateTime.UtcNow}] Expiration hit for Key: {key}");
                        var ticket = await ticketStore.RetrieveFromBackupAsync(key);
                        await AzureLogoutRequest(ticket);
                        break;
                }
            }
        });

        return Task.FromResult(0);
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        var db = 0;
        var notificationChannel = "__keyspace@" + db + "__:*";

        var subscriber = GetConnection().GetSubscriber();
        subscriber.Unsubscribe(notificationChannel);

        return Task.CompletedTask;
    }

    private string GetKey(string channel)
    {
        var index = channel.IndexOf(':');

        if (index >= 0 && index < channel.Length - 1)
            return channel.Substring(index + 1);

        return channel;
    }

    private ConnectionMultiplexer GetConnection() => lazyConnection.Value;

    private async Task AzureLogoutRequest(AuthenticationTicket ticket)
    {
        var sessionId = ticket.Principal.FindFirst(Saml2ClaimTypes.SessionIndex)?.Value;
        var email = ticket.Principal.FindFirst(Saml2ClaimTypes.NameId)?.Value;

        var utcNow = DateTime.UtcNow;
        var isoFormat = "yyyy-MM-ddTHH:mm:sssZ";

        var reqStr = $"<saml2p:LogoutRequest xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_{Guid.NewGuid()}\" Version=\"2.0\" IssueInstant=\"{utcNow.ToString(isoFormat, CultureInfo.InvariantCulture)}\" Destination=\"https://login.microsoftonline.com/9f5749d2-1a60-4dbd-981c-ae949f54a23d/saml2\" NotOnOrAfter=\"{utcNow.AddMinutes(10).ToString(isoFormat, CultureInfo.InvariantCulture)}\"><saml2:Issuer>SAML_MVC_App</saml2:Issuer><saml2:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">{email}</saml2:NameID><saml2p:SessionIndex>{sessionId}</saml2p:SessionIndex></saml2p:LogoutRequest>";

        var base64Str = Convert.ToBase64String(Encoding.UTF8.GetBytes(reqStr));

        using var httpClient = new HttpClient();
        using var formContent = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("SAMLRequest", base64Str)
        });
        var response = await httpClient.PostAsync("https://login.microsoftonline.com/9f5749d2-1a60-4dbd-981c-ae949f54a23d/saml2", formContent);
    }
}