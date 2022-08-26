using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class PolicyRule
{
    public long UserId { get; set; }

    public RoleId RoleId { get; set; }
    
    public PermissionId PermissionId { get; set; }
}