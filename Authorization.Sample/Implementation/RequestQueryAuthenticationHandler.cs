using System.Security.Claims;
using System.Text.Encodings.Web;
using Authorization.Sample.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Authorization.Sample.Implementation;

public class RequestQueryAuthenticationHandler : AuthenticationHandler<RequestQueryOptions>
{
    public RequestQueryAuthenticationHandler(IOptionsMonitor<RequestQueryOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) 
        : base(options, logger, encoder, clock)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (Request.Query.TryGetValue(Options.UserIdParameter, out var userIdValue) &&
            Enum.TryParse<BankUserId>(userIdValue, out var userIdEnum))
        {
            var userId = userIdEnum.ToString();
            
            var claims = new[] { new Claim(ClaimTypes.Name, userId) };
            var identity = new ClaimsIdentity(claims, nameof(RequestQueryAuthenticationHandler));
            var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name);
            
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
        
        return Task.FromResult(AuthenticateResult.Fail($"Missing \"{Options.UserIdParameter}\" query parameter"));
    }
}