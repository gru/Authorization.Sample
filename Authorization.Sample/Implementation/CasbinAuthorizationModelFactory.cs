using Authorization.Sample.Entities;
using Authorization.Sample.Services;
using Casbin;

namespace Authorization.Sample.Implementation;

public class CasbinAuthorizationModelFactory : IAuthorizationModelFactory<IEnforcer>
{
    private readonly ICurrentDateService _currentDateService;
    private readonly DataContext _context;
    private readonly CasbinAuthorizationModelOptions _options;

    public CasbinAuthorizationModelFactory(
        ICurrentDateService currentDateService, DataContext context, CasbinAuthorizationModelOptions options)
    {
        _currentDateService = currentDateService;
        _context = context;
        _options = options;
    }
    
    public IEnforcer PrepareModel()
    {
        var enforcer = new Enforcer(_options.ModelPath, _options.PolicyPath);

        var bankUserRoles = _context.BankUserRoles
            .Where(bur => bur.EndDate == null || bur.EndDate > _currentDateService.UtcNow);
        
        foreach (var bankUserRole in bankUserRoles)
        {
            var value1 = bankUserRole.BankUserId.ToString("d");
            var value2 = bankUserRole.RoleId.ToString("d");
            var value3 = OrganizationContextEx.ToCasbinString(
                bankUserRole.BranchId,
                bankUserRole.RegionalOfficeId,
                bankUserRole.OfficeId);
        
            enforcer.RoleManager.AddLink(value1, value2, value3);
        }

        return enforcer;
    }
}