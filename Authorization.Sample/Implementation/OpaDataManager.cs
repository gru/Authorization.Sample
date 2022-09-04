using System.Text.Json.Nodes;
using Authorization.Sample.Entities;
using Authorization.Sample.Services;

namespace Authorization.Sample.Implementation;

public class OpaDataManager : IOpaDataManager
{
    private readonly IOpaClient _opaClient;

    public OpaDataManager(IOpaClient opaClient)
    {
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