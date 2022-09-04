namespace Authorization.Sample.Implementation;

public interface IOpaDataManager
{
    IOpaDataManager PushJsonData(string json);
    
    IOpaDataManager PushJsonDataFile(string path);
}