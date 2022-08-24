using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class ResourceAuthorizationModel
{
    public ResourceAuthorizationModel(
        IQueryable<ResourcePolicyRule> resourcePolicyRules)
    {
        ResourcePolicyRules = resourcePolicyRules;
    }

    public IQueryable<ResourcePolicyRule> ResourcePolicyRules { get; }

    public bool HasPermission(long userId, SecurableId securableId, PermissionId permissionId, OrganizationContext ctx)
    {
        var query = ResourcePolicyRules
            .Where(r => r.UserId == userId && 
                        (r.Resource == securableId || r.Resource == SecurableId.Any) &&
                        (r.Action == permissionId || r.Action == PermissionId.Any));

        query = ApplyOrganizationContextFilter(query, ctx);

        return query.Any();
    }

    public IQueryable<T> ApplyOrganizationContextFilter<T>(IQueryable<T> query, OrganizationContext ctx)
        where T : IOrganizationContextRule
    {
        if (ctx == null)
        {
            query = query
                .Where(r => r.BranchId == null && r.RegionalOfficeId == null && r.OfficeId == null);
        }
        else
        {
            query = query
                .Where(r => (r.BranchId == null && r.RegionalOfficeId == null && r.OfficeId == null) ||
                            (r.BranchId == ctx.BranchId && 
                             (r.RegionalOfficeId == null || 
                              (ctx.RegionalOfficeId == null && ctx.OfficeId != null) || 
                              (r.RegionalOfficeId == ctx.RegionalOfficeId)) && 
                             (r.OfficeId == null || r.OfficeId == ctx.OfficeId)));
        }

        return query;
    }
}