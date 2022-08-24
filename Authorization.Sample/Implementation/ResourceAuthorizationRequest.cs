using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class ResourceAuthorizationRequest : ICurrentUserAuthorizationRequest
{
    public ResourceAuthorizationRequest(SecurableId resource, PermissionId action, OrganizationContext organizationContext = null)
    {
        Resource = resource;
        Action = action;
        OrganizationContext = organizationContext;
    }

    public long UserId { get; set; }
    
    public SecurableId Resource { get; }
    
    public PermissionId Action { get; }

    public OrganizationContext OrganizationContext { get; }
}