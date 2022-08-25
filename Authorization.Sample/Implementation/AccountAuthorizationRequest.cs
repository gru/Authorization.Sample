using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class AccountAuthorizationRequest : ICurrentUserAuthorizationRequest
{
    public AccountAuthorizationRequest(string gl2, PermissionId permissionId, OrganizationContext organizationContext = null)
    {
        OrganizationContext = organizationContext;
        PermissionId = permissionId;
        GL2 = gl2;
    }

    public long UserId { get; set; }
    
    public OrganizationContext OrganizationContext { get; set; }
    
    public PermissionId PermissionId { get; }
    
    public string GL2 { get; }
}