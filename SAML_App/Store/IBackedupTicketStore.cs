using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

public interface IBackedupTicketStore : ITicketStore
{
    Task<AuthenticationTicket> RetrieveFromBackupAsync(string key);
}