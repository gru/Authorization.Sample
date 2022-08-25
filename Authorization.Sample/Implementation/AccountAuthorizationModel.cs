using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class AccountAuthorizationModel : ResourceAuthorizationModel
{
    public AccountAuthorizationModel(
        IQueryable<AccountPolicyRule> accountPolicyRules,
        ILookup<string, long> gl2Lookup,
        IQueryable<ResourcePolicyRule> resourcePolicyRules,
        IQueryable<RolePolicyRule> rolePolicyRules, 
        IQueryable<Permission> permissions) 
        : base(resourcePolicyRules, rolePolicyRules, permissions)
    {
        GL2Lookup = gl2Lookup;
        AccountPolicyRules = accountPolicyRules;
    }

    public ILookup<string, long> GL2Lookup { get; }
    
    public IQueryable<AccountPolicyRule> AccountPolicyRules { get; }

    public bool HasAnyAccountAccess(long userId)
    {
        return ResourcePolicyRules
            .Any(r => r.UserId == userId && 
                      (r.SecurableId == SecurableId.Account || r.SecurableId == SecurableId.Any)  &&
                      (r.PermissionId == PermissionId.Any));
    }
}