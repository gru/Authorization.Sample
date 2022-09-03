using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Authorization.Sample.Entities;
using Microsoft.AspNetCore.Authorization;
using OPADotNet.Ast;
using OPADotNet.Core.Models;

namespace Authorization.Sample.Services;

public class AuthSchemas
{
    public const string RequestQueryScheme = "RequestQuery";
}

public static class AuthorizationOptionsEx
{
    public static AuthorizationOptions AddResourcePolicy(this AuthorizationOptions options, SecurableId securableId, PermissionId permissionId, Action<AuthorizationPolicyBuilder> action)
    {
        options.AddPolicy($"{securableId}.{permissionId}", action);
        return options;
    }
}

public static class AuthorizationPolicyBuilderEx
{
    public static AuthorizationPolicyBuilder AddResourceRequirement(this AuthorizationPolicyBuilder builder, SecurableId resource, PermissionId operation)
    {
        return builder.AddRequirements(new OpaRequirement("resource", resource.ToString(), operation.ToString()));
    }
    
    public static AuthorizationPolicyBuilder AddOpaRequirement(this AuthorizationPolicyBuilder builder, string name, string resource = "", string operation = "")
    {
        return builder.AddRequirements(new OpaRequirement(name, resource, operation));
    }
}

public class OpaRequirement : IAuthorizationRequirement
{
    public OpaRequirement(string name, string resource, string operation)
    {
        Name = name;
        Resource = resource;
        Operation = operation;
    }

    public string Name { get; }

    public string Resource { get; }

    public string Operation { get; }

    public string GetQuery()
    {
        return $"data.{Name}.allow == true";
    }

    public IEnumerable<string> GetUnknowns()
    {
        if (Resource != null)
            yield return $"data.{Resource}";
    }
}

public class OpaAuthorizationHandler : AuthorizationHandler<OpaRequirement>
{
    private readonly IOpaClient _opaClient;

    public OpaAuthorizationHandler(IOpaClient opaClient)
    {
        _opaClient = opaClient;
    }

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, OpaRequirement requirement)
    {
        var query = requirement.GetQuery();
        var unknowns = requirement.GetUnknowns();
        var subject = OpaInputUser.FromPrincipal(context.User);
        var input = new OpaInput
        {
            Subject = subject,
            Operation = requirement.Operation
        };

        var compile = await _opaClient.Compile(query, input, unknowns);
        if (compile.Result.Queries != null)
            context.Succeed(requirement);
    }
}

public interface IOpaClient
{
    Task<PartialResult> Compile(string query, object input, IEnumerable<string> unknowns);

    Task CreateOrUpdatePolicy(string name, string query);

    Task CreateData(string name, string json);
    
    Task DeleteData(string name);
}

public class OpaHttpClient : IOpaClient
{
    private readonly HttpClient _httpClient;

    public OpaHttpClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }
    
    public async Task<PartialResult> Compile(string query, object input, IEnumerable<string> unknowns)
    {
        var result = await _httpClient.PostAsJsonAsync("/v1/compile", new
        {
            Input = input,
            Query = query,
            Unknowns = unknowns
        });

        var content = await result.Content.ReadAsStringAsync();
        var partialResult = PartialJsonConverter.ReadPartialResult(content);
        return partialResult;
    }

    public async Task CreateOrUpdatePolicy(string name, string query)
    {
        var result = await _httpClient.PostAsync($"/v1/policies/{name}", new StringContent(query, Encoding.UTF8, "text/plain"));
        
        result.EnsureSuccessStatusCode();
    }

    public async Task CreateData(string name, string json)
    {
        var result = await _httpClient.PutAsync($"/v1/data/{name}", new StringContent(json, Encoding.UTF8, "application/json"));

        result.EnsureSuccessStatusCode();
    }

    public async Task DeleteData(string name)
    {
        var result = await _httpClient.DeleteAsync($"/v1/data/{name}");

        result.EnsureSuccessStatusCode();
    }
}

internal class OpaInput
{
    [JsonPropertyName("subject")]
    public OpaInputUser Subject { get; set; }

    [JsonPropertyName("operation")]
    public string Operation { get; set; }

    [JsonExtensionData]
    public Dictionary<string, object> Extensions { get; set; }
}

internal class OpaInputUser
{
    [JsonPropertyName("name")]
    public string Name { get; set; }

    [JsonPropertyName("claims")]
    public Dictionary<string, List<string>> Claims { get; set; }

    [JsonPropertyName("isAuthenticated")]
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

public interface IOpaManager
{
    void PushPolicy(string name, string query);
    
    void PushPolicyFile(string name, string path);
}

public class OpaManager : IOpaManager
{
    private readonly IOpaClient _opaClient;

    public OpaManager(IOpaClient opaClient)
    {
        _opaClient = opaClient;
    }
    
    public void PushPolicy(string name, string query)
    {
        _opaClient.CreateOrUpdatePolicy(name, query);
    }

    public void PushPolicyFile(string name, string path)
    {
        var query = File.ReadAllText(path);
        
        PushPolicy(name, query);
    }
}

public interface IOpaDataManager
{
    IOpaDataManager PushRoles();

    IOpaDataManager PushUserRoles();

    IOpaDataManager PushReadOnlyPermissions();
}

public class OpaDataManager : IOpaDataManager
{
    private readonly DataContext _context;
    private readonly ICurrentDateService _dateService;
    private readonly IOpaClient _opaClient;

    public OpaDataManager(DataContext context, ICurrentDateService dateService, IOpaClient opaClient)
    {
        _context = context;
        _dateService = dateService;
        _opaClient = opaClient;
    }
    
    public IOpaDataManager PushRoles()
    {
        static string ToPermissionValue(PermissionId permissionId) => 
            permissionId != PermissionId.Any ? permissionId.ToString() : "*";

        static string ToSecurableValue(SecurableId securableId) => 
            securableId != SecurableId.Any ? securableId.ToString() : "*";

        var rolePermissions = _context.RolePermissions
            .ToArray()
            .Select(rp => new
            {
                role = rp.RoleId, 
                securable = ToSecurableValue(rp.SecurableId), 
                permission = ToPermissionValue(rp.PermissionId)
            })
            .GroupBy(rp => rp.role)
            .ToDictionary(
                g => g.Key,
                g => g.Select(rp => new { rp.securable, rp.permission }));

        var data = JsonSerializer.Serialize(rolePermissions);

        _opaClient.DeleteData(nameof(rolePermissions));
        _opaClient.CreateData(nameof(rolePermissions), data);

        return this;
    }

    public IOpaDataManager PushUserRoles()
    {
        static string ToOrgContextValue(long? value) => 
            value.HasValue ? value.ToString() : "*";

        var userRoles = _context.BankUserRoles
            .Where(ur => ur.EndDate == null || ur.EndDate > _dateService.UtcNow)
            .ToArray()
            .Select(ur => new
            {
                user = ur.BankUserId.ToString(),
                role = ur.RoleId.ToString(),
                orgContext = new
                {
                    branch = ToOrgContextValue(ur.BranchId),
                    regOffice = ToOrgContextValue(ur.RegionalOfficeId),
                    office = ToOrgContextValue(ur.OfficeId)
                }
            })
            .GroupBy(ur => ur.user)
            .ToDictionary(
                g => g.Key, 
                g => g.Select(ur => new { ur.role, ur.orgContext }));
        
        var data = JsonSerializer.Serialize(userRoles);
        
        _opaClient.DeleteData(nameof(userRoles));
        _opaClient.CreateData(nameof(userRoles), data);

        return this;
    }

    public IOpaDataManager PushReadOnlyPermissions()
    {
        var readOnlyPermissions = _context.Permissions
            .Where(p => p.IsReadonly)
            .Select(p => p.Id.ToString());
        
        var data = JsonSerializer.Serialize(readOnlyPermissions);

        _opaClient.DeleteData(nameof(readOnlyPermissions));
        _opaClient.CreateData(nameof(readOnlyPermissions), data);

        return this;
    }
}