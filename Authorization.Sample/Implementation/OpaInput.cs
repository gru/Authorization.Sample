using System.Text.Json.Serialization;

namespace Authorization.Sample.Implementation;

internal class OpaInput
{
    public OpaInputUser Subject { get; set; }

    public string PermissionId { get; set; }
    
    public object SecurableId { get; set; }

    [JsonExtensionData]
    public Dictionary<string, object> Extensions { get; set; }
}