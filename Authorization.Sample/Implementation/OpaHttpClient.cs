using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Authorization.Sample.Services;
using OPADotNet.Ast;
using OPADotNet.Core.Models;

namespace Authorization.Sample.Implementation;

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
        
        var message = await _httpClient.PostAsync("/v1/compile", new StringContent(data, Encoding.UTF8, "application/json"));

        message.EnsureSuccessStatusCode();
            
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
    
    private struct EvalResult
    {
        [JsonPropertyName("result")]
        public bool Result { get; set; }
    }
}