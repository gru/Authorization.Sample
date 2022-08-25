using Authorization.Sample.Entities;
using Authorization.Sample.Services;

namespace Authorization.Sample.Implementation;

public class AccountAuthorizationModelFactory : ResourceAuthorizationModelFactory, IAuthorizationModelFactory<AccountAuthorizationModel>
{
    private readonly DataContext _context;

    public AccountAuthorizationModelFactory(DataContext context, ICurrentDateService dateService) 
        : base(context, dateService)
    {
        _context = context;
    }

    public new AccountAuthorizationModel PrepareModel()
    {
        var model = new AccountAuthorizationModel(
            GetAccountPolicyRules(), 
            GetGL2Lookup(),
            GetResourcePolicyRules(), 
            GetRolePolicyRules(), 
            GetPermissions());

        return model;
    }

    private IQueryable<AccountPolicyRule> GetAccountPolicyRules()
    {
        return from bankUserRole in _context.BankUserRoles
            join gl2GroupRolePermission in _context.Gl2GroupRolePermissions on bankUserRole.RoleId equals gl2GroupRolePermission.RoleId
            select new AccountPolicyRule
            {
                UserId = (int)bankUserRole.BankUserId,
                PermissionId = gl2GroupRolePermission.PermissionId,
                GL2GroupId = gl2GroupRolePermission.GL2GroupId,
                BranchId = bankUserRole.BranchId,
                RegionalOfficeId = bankUserRole.RegionalOfficeId,
                OfficeId = bankUserRole.OfficeId
            };
    }

    private ILookup<string, long> GetGL2Lookup()
    {
        return _context.Gl2Groups
            .Select(g => new { g.GL2GroupId, g.GL2 })
            .ToLookup(g => g.GL2, g => g.GL2GroupId);
    }
}