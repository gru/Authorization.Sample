using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public static class DocumentPermissions
{
    public const string View = $"{nameof(SecurableId.Document)}.{nameof(PermissionId.View)}";
    public const string Create = $"{nameof(SecurableId.Document)}.{nameof(PermissionId.Create)}";
    public const string Change = $"{nameof(SecurableId.Document)}.{nameof(PermissionId.Change)}";
    public const string Delete = $"{nameof(SecurableId.Document)}.{nameof(PermissionId.Delete)}";

    public static (SecurableId securableId, PermissionId permissionId) Parse(string permission)
    {
        var arr = permission.Split('.');
        return (Enum.Parse<SecurableId>(arr[0]), Enum.Parse<PermissionId>(arr[1]));
    }
}