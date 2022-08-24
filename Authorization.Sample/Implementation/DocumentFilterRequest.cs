using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class DocumentFilterRequest : ICurrentUserAuthorizationRequest
{
    public DocumentFilterRequest(OrganizationContext organizationContext = null, PermissionId permissionId = PermissionId.View)
    {
        PermissionId = permissionId;
        OrganizationContext = organizationContext;
    }

    public long UserId { get; set; }
    
    public PermissionId PermissionId { get; }
    
    public OrganizationContext OrganizationContext { get; }
}