using Authorization.Sample.Entities;
using Casbin;

namespace Authorization.Sample.Implementation;

public class AccountCasbinMatcher : Matcher<AccountAuthorizationRequest, IEnforcer>
{
    private readonly Lazy<ILookup<string,long>> _gl2Lookup;

    public AccountCasbinMatcher(IAuthorizationModelFactory<IEnforcer> modelFactory, DataContext context) 
        : base(modelFactory)
    {
        _gl2Lookup = new Lazy<ILookup<string, long>>(() => 
            context.Gl2Groups
                .Select(g => new { g.GL2GroupId, g.GL2 })
                .ToLookup(g => g.GL2, g => g.GL2GroupId));
    }

    protected override bool Match(AccountAuthorizationRequest request, IEnforcer enforcer)
    {
        var sub = request.UserId.ToString();
        var act = request.PermissionId.ToString();
        var ctx = request.OrganizationContext.ToCasbinString();

        var enforceContext = EnforceContext
            .Create(enforcer, policyType: "p3", matcherType: "m3");
        
        foreach (var gl2GroupId in _gl2Lookup.Value[request.GL2])
        {
            var obj = gl2GroupId.ToString();
            
            if (enforcer.Enforce(enforceContext, sub, obj, act, ctx))
                return true;
        }
        
        return false;
    }
}