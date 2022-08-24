namespace Authorization.Sample.Entities;

public class RolePermission
{
    public RoleId RoleId { get; set; }
    
    public SecurableId SecurableId { get; set; }
    
    public PermissionId PermissionId { get; set; }
}