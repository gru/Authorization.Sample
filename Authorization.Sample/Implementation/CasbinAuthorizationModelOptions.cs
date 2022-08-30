namespace Authorization.Sample.Implementation;

public class CasbinAuthorizationModelOptions
{
    public string ModelPath { get; set; } = "model.conf";

    public string PolicyPath { get; set; } = "policy.csv";
}