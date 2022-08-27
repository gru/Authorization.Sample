using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class DefaultFilterRequest : ICurrentUserAuthorizationRequest
{
    public DefaultFilterRequest(OrganizationContext organizationContext = null, PermissionId permissionId = PermissionId.View)
    {
        PermissionId = permissionId;
        OrganizationContext = organizationContext;
    }

    public long UserId { get; set; }

    public OrganizationContext OrganizationContext { get; set; }

    public PermissionId PermissionId { get; }
}