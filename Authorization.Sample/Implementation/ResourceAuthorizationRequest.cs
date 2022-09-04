using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class ResourceAuthorizationRequest
{
    public ResourceAuthorizationRequest(SecurableId securableId, PermissionId permissionId, OrganizationContext organizationContext = null)
    {
        SecurableId = securableId;
        PermissionId = permissionId;
        OrganizationContext = organizationContext;
    }

    public long UserId { get; set; }
    
    public OrganizationContext OrganizationContext { get; set; }
    
    public SecurableId SecurableId { get; }
    
    public PermissionId PermissionId { get; }
}