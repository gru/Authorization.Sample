using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class AccountMatcher : Matcher<AccountAuthorizationRequest, AuthorizationModel>
{
    public AccountMatcher(IAuthorizationModelFactory<AuthorizationModel> modelFactory) 
        : base(modelFactory)
    {
    }

    protected override bool Match(AccountAuthorizationRequest request, AuthorizationModel model)
    {
        return model.HasGL2Permission(
            userId: request.UserId,
            gl2: request.GL2,
            permissionId: request.PermissionId, 
            organizationContext: request.OrganizationContext);
    }
}