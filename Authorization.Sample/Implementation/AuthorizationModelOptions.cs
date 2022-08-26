namespace Authorization.Sample.Implementation;

public class AuthorizationModelOptions
{
    public AuthorizationModelOptions(bool allowReadPermissionsOnly)
    {
        AllowReadPermissionsOnly = allowReadPermissionsOnly;
    }

    public bool AllowReadPermissionsOnly { get; }
}