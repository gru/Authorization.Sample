using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class ResourcePermissionMatcher : Matcher<ResourceAuthorizationRequest, AuthorizationModel>
{
    public ResourcePermissionMatcher(
        IAuthorizationModelFactory<AuthorizationModel> modelFactory) 
        : base(modelFactory)
    {
    }

    protected override IEnumerable<PolicyEffect> Match(ResourceAuthorizationRequest request, AuthorizationModel model)
    {
        if (model.InRole(request.UserId, RoleId.Superuser))
        {
            yield return PolicyEffect.Allow;
        }
        else
        {
            foreach (var rule in model.UserPolicyRules(request.UserId, request.PermissionId, request.OrganizationContext))
            {
                if (model.InResourceRole(request.UserId, rule.RoleId, request.SecurableId, rule.PermissionId))
                    yield return PolicyEffect.Allow;
            }
        }
    }
}