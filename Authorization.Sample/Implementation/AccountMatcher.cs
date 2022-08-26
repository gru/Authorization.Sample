using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class AccountMatcher : Matcher<AccountAuthorizationRequest, AuthorizationModel>
{
    public AccountMatcher(IAuthorizationModelFactory<AuthorizationModel> modelFactory) 
        : base(modelFactory)
    {
    }

    protected override IEnumerable<PolicyEffect> Match(AccountAuthorizationRequest request, AuthorizationModel model)
    {
        foreach (var rule in model.UserPolicyRules(request.UserId, request.PermissionId, request.OrganizationContext))
        {
            if (model.InRole(request.UserId, RoleId.Superuser) ||
                model.InGL2GroupRole(request.UserId, rule.RoleId, request.GL2) ||
                model.InResourceRole(request.UserId, rule.RoleId, SecurableId.Account, rule.PermissionId))
            {
                yield return PolicyEffect.Allow;
            }
        }
    }
}