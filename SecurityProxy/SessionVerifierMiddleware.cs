using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;

namespace SecurityProxy;

internal class SessionVerifierMiddleware
{
    private readonly RequestDelegate next;

    public SessionVerifierMiddleware(RequestDelegate next) => this.next = next;

    public async Task InvokeAsync(HttpContext context, ITicketStore ticketStore)
    {
        var sessionId = context.Request.Headers["Session-Id"];
        if (string.IsNullOrEmpty(sessionId))
        {
            context.Response.StatusCode = 401;
            return;
        }

        var ticket = await ticketStore.RetrieveAsync(sessionId);
        if(ticket is null)
        {
            context.Response.StatusCode = 401;
            return;
        }
        await next.Invoke(context);
    }
}