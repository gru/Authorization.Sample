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
        if (model.InGL2GroupRole(request.UserId, request.GL2, request.PermissionId, request.OrganizationContext) ||
            model.InResourceRole(request.UserId, SecurableId.Account, request.PermissionId, request.OrganizationContext))
        {
            yield return PolicyEffect.Allow;
        }
    }
}