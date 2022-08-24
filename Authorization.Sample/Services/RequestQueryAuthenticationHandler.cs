using System.Security.Claims;
using System.Text.Encodings.Web;
using Authorization.Sample.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Authorization.Sample.Services;

public class RequestQueryAuthenticationHandler : AuthenticationHandler<RequestQueryOptions>
{
    public RequestQueryAuthenticationHandler(IOptionsMonitor<RequestQueryOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) 
        : base(options, logger, encoder, clock)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (Request.Query.TryGetValue(Options.UserIdParameter, out var userIdValue))
        {
            if (Enum.TryParse<BankUserId>(userIdValue, out var userIdEnumValue))
                userIdValue = ((int)userIdEnumValue).ToString();
            else if (int.TryParse(userIdValue, out var userIdIntValue))
                userIdValue = userIdIntValue.ToString();
            else return Task.FromResult(AuthenticateResult.Fail($"Unable to parse \"{Options.UserIdParameter}\" query parameter"));
            
            var claims = new[] { new Claim(ClaimTypes.Name, userIdValue) };
            var identity = new ClaimsIdentity(claims, nameof(RequestQueryAuthenticationHandler));
            var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name);
            
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
        
        return Task.FromResult(AuthenticateResult.Fail($"Missing \"{Options.UserIdParameter}\" query parameter"));
    }
}