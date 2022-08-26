using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class ResourceAuthorizationRequest : ICurrentUserAuthorizationRequest
{
    public ResourceAuthorizationRequest(SecurableId resource, PermissionId permissionId, OrganizationContext organizationContext = null)
    {
        Resource = resource;
        PermissionId = permissionId;
        OrganizationContext = organizationContext;
    }

    public long UserId { get; set; }
    
    public OrganizationContext OrganizationContext { get; set; }
    
    public SecurableId Resource { get; }
    
    public PermissionId PermissionId { get; }
}