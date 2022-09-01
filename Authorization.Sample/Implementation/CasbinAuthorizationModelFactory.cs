using Authorization.Sample.Entities;
using Authorization.Sample.Services;
using Casbin;
using Casbin.Rbac;

namespace Authorization.Sample.Implementation;

public class CasbinAuthorizationModelFactory : IAuthorizationModelFactory<IEnforcer>
{
    private readonly ICurrentDateService _currentDateService;
    private readonly IDemoService _demoService;
    private readonly DataContext _context;
    private readonly CasbinAuthorizationModelOptions _options;

    public CasbinAuthorizationModelFactory(
        ICurrentDateService currentDateService, IDemoService demoService, DataContext context, CasbinAuthorizationModelOptions options)
    {
        _currentDateService = currentDateService;
        _demoService = demoService;
        _context = context;
        _options = options;
    }

    public IEnforcer PrepareModel()
    {
        var enforcer = new Enforcer(_options.ModelPath, _options.PolicyPath);
        enforcer.AddFunction("act_allowed", IsReadOnlyPermission);
        
        var roleManager = new DefaultRoleManager(0);
        roleManager.AddDomainMatchingFunc((arg1, arg2) => arg1 == arg2);
        enforcer.Model.SetRoleManager("g", roleManager);
        
        var bankUserRoles = _context.BankUserRoles
            .Where(bur => bur.EndDate == null || bur.EndDate > _currentDateService.UtcNow);
        
        foreach (var bankUserRole in bankUserRoles)
        {
            var value1 = bankUserRole.BankUserId.ToString();
            var value2 = bankUserRole.RoleId.ToString();
            var value3 = OrganizationContextEx.ToCasbinString(
                bankUserRole.BranchId,
                bankUserRole.RegionalOfficeId,
                bankUserRole.OfficeId);
        
            enforcer.AddGroupingPolicy(value1, value2, value3);
        }

        enforcer.Model.BuildRoleLinks();
        
        roleManager.AddDomainMatchingFunc(DomainMatchingFunction);

        return enforcer;
    }

    private static bool DomainMatchingFunction(string arg1, string arg2)
    {
        if (arg1 == arg2) 
            return true;
        
        if (arg1 == string.Empty || arg2 == string.Empty)
            return arg1 == arg2;
        
        var bur = arg2.Split('/');

        var burBranchId = bur[0];
        var burRegionalOfficeId = bur[1];
        var burOfficeId = bur[2];

        var ctx = arg1.Split('/');
        
        var ctxBranchId = ctx[0];
        var ctxRegionalOfficeId = ctx[1];
        var ctxOfficeId = ctx[2];

        return (burBranchId == "*" && burRegionalOfficeId == "*" && burOfficeId == "*") ||
               (burBranchId == ctxBranchId && 
                (burRegionalOfficeId == "*" || 
                 (ctxRegionalOfficeId == "*" && ctxOfficeId != "*") || 
                 (burRegionalOfficeId == ctxRegionalOfficeId)) && 
                (burOfficeId == "*" || burOfficeId == ctxOfficeId));
    }

    private bool IsReadOnlyPermission(string permissionId)
    {
        if (!_demoService.IsDemoModeActive) 
            return true;
        
        if (permissionId == "*") 
            return false;
        
        var id = Enum.Parse<PermissionId>(permissionId);
        return _context.Permissions.Any(p => p.Id == id && p.IsReadonly);
    }
}