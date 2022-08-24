using Microsoft.AspNetCore.Authentication;

namespace Authorization.Sample.Services;

public class RequestQueryOptions : AuthenticationSchemeOptions
{
    public string UserIdParameter { get; set; } = "userId";
}