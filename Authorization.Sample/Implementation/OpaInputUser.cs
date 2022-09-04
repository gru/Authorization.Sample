using System.Security.Claims;
using System.Text.Json.Serialization;

namespace Authorization.Sample.Implementation;

internal class OpaInputUser
{
    [JsonPropertyName("Name")]
    public string Name { get; set; }

    [JsonPropertyName("Claims")]
    public Dictionary<string, List<string>> Claims { get; set; }

    [JsonPropertyName("Authenticated")]
    public bool IsAuthenticated { get; set; }

    public static OpaInputUser FromPrincipal(ClaimsPrincipal claimsPrincipal)
    {
        var output = new OpaInputUser
        {
            Name = claimsPrincipal?.Identity?.Name,
            Claims = new Dictionary<string, List<string>>(),
            IsAuthenticated = claimsPrincipal?.Identity?.IsAuthenticated ?? false
        };

        if (claimsPrincipal?.Claims != null)
        {
            foreach (var claim in claimsPrincipal.Claims)
            {
                if (!output.Claims.TryGetValue(claim.Type, out var claims))
                {
                    claims = new List<string>();
                    output.Claims.Add(claim.Type, claims);
                }
                claims.Add(claim.Value);
            }
        }

        return output;
    }
}