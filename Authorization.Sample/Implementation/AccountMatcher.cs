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
        if (model.HasGL2Permission(request.UserId, request.GL2, request.PermissionId, request.OrganizationContext))
            yield return PolicyEffect.Allow;
    }
}