using OPADotNet.Core.Models;

namespace Authorization.Sample.Implementation;

public interface IOpaClient
{
    Task<PartialResult> Compile(string query, object input, IEnumerable<string> unknowns);
    
    Task<bool> Evaluate(string policy, object input);

    Task CreateOrUpdatePolicy(string name, string query);

    Task CreateData(string name, string json);
    
    Task DeleteData(string name);
}