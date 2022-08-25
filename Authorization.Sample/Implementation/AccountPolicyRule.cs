using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class AccountPolicyRule : IOrganizationContextRule
{
    public long UserId { get; set; }

    public long GL2GroupId { get; set; }
    
    public PermissionId PermissionId { get; set; }
    
    public long? BranchId { get; set; }
    
    public long? RegionalOfficeId { get; set; }
    
    public long? OfficeId { get; set; }
}