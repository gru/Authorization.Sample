using System.Text.Json.Serialization;

namespace Authorization.Sample.Implementation;

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