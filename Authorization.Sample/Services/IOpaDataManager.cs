namespace Authorization.Sample.Services;

public interface IOpaDataManager
{
    IOpaDataManager PushJsonData(string json);
    
    IOpaDataManager PushJsonDataFile(string path);
}