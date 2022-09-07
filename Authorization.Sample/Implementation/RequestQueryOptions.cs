using Microsoft.AspNetCore.Authentication;

namespace Authorization.Sample.Implementation;

public class RequestQueryOptions : AuthenticationSchemeOptions
{
    public string UserIdParameter { get; set; } = "userId";
}