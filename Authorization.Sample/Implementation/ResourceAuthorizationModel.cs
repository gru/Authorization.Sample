using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class ResourceAuthorizationModel
{
    public ResourceAuthorizationModel(
        IQueryable<ResourcePolicyRule> resourcePolicyRules, 
        IQueryable<RolePolicyRule> rolePolicyRules,
        IQueryable<Permission> permissions)
    {
        ResourcePolicyRules = resourcePolicyRules;
        RolePolicyRules = rolePolicyRules;
        Permissions = permissions;
    }

    public IQueryable<Permission> Permissions { get; }
    
    public IQueryable<ResourcePolicyRule> ResourcePolicyRules { get; }

    public IQueryable<RolePolicyRule> RolePolicyRules { get; }

    public bool IsSuperuser(long userId)
    {
        return RolePolicyRules.Any(r => r.UserId == userId && r.RoleName == "Superuser");
    }

    public bool IsReadOnlyPermission(PermissionId permissionId)
    {
        /*
         * NOTE:
         * Так как существуют разрешения Any, которые являются одновременно и ReadOnly и нет,
         * то нельзя просто отфитровать все не ReadOnly разрешения на этапе построения модели.
         * Поэтому проверяем запрашиваемое разрешение, на признак IsReadOnly
         */
        
        return Permissions.Any(p => p.Id == permissionId && p.IsReadonly);
    }
    
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