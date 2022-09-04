using Microsoft.AspNetCore.Authorization;

namespace Authorization.Sample.Implementation;

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