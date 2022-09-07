using Authorization.Sample.Services;

namespace Authorization.Sample.Implementation;

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