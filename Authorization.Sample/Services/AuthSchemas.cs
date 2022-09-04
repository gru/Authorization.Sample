using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Authorization.Sample.Entities;
using Microsoft.AspNetCore.Authorization;
using OPADotNet.Ast;
using OPADotNet.Core.Models;
using static Authorization.Sample.Services.OrgContextHelpers;

namespace Authorization.Sample.Services;

public class AuthSchemas
{
    public const string RequestQueryScheme = "RequestQuery";
}

public static class AuthorizationPolicyBuilderEx
{
    public static AuthorizationPolicyBuilder AddOpaResourceRequirement(this AuthorizationPolicyBuilder builder, string name, SecurableId securableId, PermissionId permissionId)
    {
        return builder.AddRequirements(new OpaRequirement(name, securableId.ToString(), permissionId.ToString()));
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

    public string GetPolicy()
    {
        return $"{Name.Replace('.', '/')}/allow" ;
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
    private readonly IHttpContextAccessor _contextAccessor;

    public OpaAuthorizationHandler(IOpaClient opaClient, IHttpContextAccessor contextAccessor)
    {
        _opaClient = opaClient;
        _contextAccessor = contextAccessor;
    }

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, OpaRequirement requirement)
    {
        var policy = requirement.GetPolicy();
        var subject = OpaInputUser.FromPrincipal(context.User);
        var (branch, regOffice, office) = GetOrganizationContext();
        var input = new OpaInput
        {
            Subject = subject,
            Action = requirement.Operation,
            Object = requirement.Resource,
            Extensions = new Dictionary<string, object>
            {
                ["orgContext"] = new
                {
                    branch = ToOrgContextValue(branch),
                    regOffice = ToOrgContextValue(regOffice),
                    office = ToOrgContextValue(office),
                }
            }
        };

        var result = await _opaClient.Evaluate(policy, input);
        if (result) context.Succeed(requirement);
    }

    private (long?, long?, long?) GetOrganizationContext()
    {
        var query = _contextAccessor.HttpContext?.Request.Query;
        if (query != null)
        {
            if (query.TryGetValue("branchId", out var branchIdString) && 
                long.TryParse(branchIdString, out var branchId))
            {
                long? regionalOfficeId = 
                    query.TryGetValue("regionalOfficeId", out var regionalOfficeIdString) && long.TryParse(regionalOfficeIdString, out var regionalOfficeIdValue)
                        ? regionalOfficeIdValue
                        : null;

                long? officeId = 
                    query.TryGetValue("regionalOfficeId", out var officeIdString) && long.TryParse(officeIdString, out var officeIdValue)
                        ? officeIdValue
                        : null;

                return (branchId, regionalOfficeId, officeId);
            }
        }

        return (null, null, null);
    }
}

public interface IOpaClient
{
    Task<PartialResult> Compile(string query, object input, IEnumerable<string> unknowns);
    
    Task<bool> Evaluate(string policy, object input);

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
        var data = JsonSerializer.Serialize(new
        {
            Input = input,
            Query = query,
            Unknowns = unknowns
        });
        
        var message = (await _httpClient.PostAsync("/v1/compile", new StringContent(data, Encoding.UTF8, "application/json")))
            .EnsureSuccessStatusCode();
        
        var content = await message.Content.ReadAsStringAsync();
        var result = PartialJsonConverter.ReadPartialResult(content);
        
        return result;
    }

    public async Task<bool> Evaluate(string policy, object input)
    {
        var data = JsonSerializer.Serialize(new
        {
            input = input
        });
        
        var message = (await _httpClient.PostAsync($"/v1/data/{policy}", new StringContent(data, Encoding.UTF8, "application/json")))
            .EnsureSuccessStatusCode();
        
        var content = await message.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<EvalResult>(content);
        
        return result.Result;
    }

    public async Task CreateOrUpdatePolicy(string name, string query)
    {
        var result = await _httpClient.PutAsync($"/v1/policies/{name}", new StringContent(query, Encoding.UTF8, "text/plain"));

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

internal struct EvalResult
{
    [JsonPropertyName("result")]
    public bool Result { get; set; }
}

internal class OpaInput
{
    [JsonPropertyName("subject")]
    public OpaInputUser Subject { get; set; }

    [JsonPropertyName("action")]
    public string Action { get; set; }
    
    [JsonPropertyName("object")]
    public object Object { get; set; }

    [JsonExtensionData]
    public Dictionary<string, object> Extensions { get; set; }
}

internal class OpaInputUser
{
    [JsonPropertyName("name")]
    public string Name { get; set; }

    [JsonPropertyName("claims")]
    public Dictionary<string, List<string>> Claims { get; set; }

    [JsonPropertyName("authenticated")]
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
    IOpaManager PushPolicy(string name, string query);
    
    IOpaManager PushPolicyFile(string name, string path);
}

public class OpaManager : IOpaManager
{
    private readonly IOpaClient _opaClient;

    public OpaManager(IOpaClient opaClient)
    {
        _opaClient = opaClient;
    }
    
    public IOpaManager PushPolicy(string name, string query)
    {
        _opaClient.CreateOrUpdatePolicy(name, query).Wait();

        return this;
    }

    public IOpaManager PushPolicyFile(string name, string path)
    {
        var query = File.ReadAllText(path);
        
        PushPolicy(name, query);
        
        return this;
    }
}

public interface IOpaDataManager
{
    IOpaDataManager PushJsonData(string json);
    
    IOpaDataManager PushJsonDataFile(string path);
}

public class OpaDataManager : IOpaDataManager
{
    private readonly DataContext _context;
    private readonly ICurrentDateService _dateService;
    private readonly IDemoService _demoService;
    private readonly IOpaClient _opaClient;

    public OpaDataManager(
        DataContext context, 
        ICurrentDateService dateService,
        IDemoService demoService,
        IOpaClient opaClient)
    {
        _context = context;
        _dateService = dateService;
        _demoService = demoService;
        _opaClient = opaClient;
    }
    
    public IOpaDataManager PushJsonData(string json)
    {
        var data = JsonNode.Parse(json)!.AsObject();
        foreach (var property in data)
        {
            _opaClient.CreateData(property.Key, property.Value!.ToJsonString()).Wait();    
        }

        return this;
    }

    public IOpaDataManager PushJsonDataFile(string path)
    {
        var data = File.ReadAllText(path);

        PushJsonData(data);

        return this;
    }
}

public static class OrgContextHelpers
{
    public static string ToOrgContextValue(long? value) => 
        value.HasValue ? value.ToString() : "*";
}