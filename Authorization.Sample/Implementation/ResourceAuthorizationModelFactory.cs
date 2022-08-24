using Authorization.Sample.Entities;
using Authorization.Sample.Services;

namespace Authorization.Sample.Implementation;

public class ResourceAuthorizationModelFactory : IAuthorizationModelFactory<ResourceAuthorizationModel>
{
    private readonly DataContext _context;
    private readonly ICurrentDateService _dateService;

    public ResourceAuthorizationModelFactory(
        DataContext context, ICurrentDateService dateService)
    {
        _context = context;
        _dateService = dateService;
    }

    public ResourceAuthorizationModel PrepareModel()
    {
        var model = new ResourceAuthorizationModel(GetResourcePolicyRules(), GetRolePolicyRules(), GetPermissionQuery());
        return model;
    }

    protected IQueryable<ResourcePolicyRule> GetResourcePolicyRules()
    {
        return from bankUserRole in _context.BankUserRoles
            join rolePermission in _context.RolePermissions on bankUserRole.RoleId equals rolePermission.RoleId
            join permission in _context.Permissions on rolePermission.PermissionId equals  permission.Id
            where bankUserRole.EndDate == null || bankUserRole.EndDate > _dateService.UtcNow
            select new ResourcePolicyRule
            {
                UserId = (long) bankUserRole.BankUserId, 
                Resource = rolePermission.SecurableId,
                Action = rolePermission.PermissionId, 
                BranchId = bankUserRole.BranchId,
                RegionalOfficeId = bankUserRole.RegionalOfficeId,
                OfficeId = bankUserRole.OfficeId
            };
    }

    protected IQueryable<RolePolicyRule> GetRolePolicyRules()
    {
        return from bankUserRole in _context.BankUserRoles
            join role in _context.Roles on bankUserRole.RoleId equals role.Id
            where bankUserRole.EndDate == null || bankUserRole.EndDate > _dateService.UtcNow
            select new RolePolicyRule
            {
                UserId = (long) bankUserRole.BankUserId, 
                RoleName = role.Name, 
            };
    }

    protected IQueryable<Permission> GetPermissionQuery()
    {
        return _context.Permissions;
    }
}