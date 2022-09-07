namespace Authorization.Sample.Services;

public interface IOpaManager
{
    IOpaManager PushPolicy(string name, string query);
    
    IOpaManager PushPolicyFile(string name, string path);
}