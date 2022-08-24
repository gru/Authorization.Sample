using Authorization.Sample.Entities;
using Authorization.Sample.Services;

namespace Authorization.Sample.Implementation;

public class ResourceAuthorizationModelFactory : IAuthorizationModelFactory<ResourceAuthorizationModel>
{
    private readonly DataContext _context;
    private readonly IDemoService _demoService;
    private readonly ICurrentDateService _dateService;

    public ResourceAuthorizationModelFactory(
        DataContext context, IDemoService demoService, ICurrentDateService dateService)
    {
        _context = context;
        _demoService = demoService;
        _dateService = dateService;
    }

    public ResourceAuthorizationModel PrepareModel()
    {
        var model = new ResourceAuthorizationModel(GetResourcePolicyRules());
        return model;
    }

    protected IQueryable<ResourcePolicyRule> GetResourcePolicyRules()
    {
        return from bankUserRole in _context.BankUserRoles
            join rolePermission in _context.RolePermissions on bankUserRole.RoleId equals rolePermission.RoleId
            join permission in _context.Permissions on rolePermission.PermissionId equals  permission.Id
            where (bankUserRole.EndDate == null || bankUserRole.EndDate > _dateService.UtcNow) && (!_demoService.IsDemoModeActive || permission.IsReadonly)
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
}