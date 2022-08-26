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
        foreach (var rule in model.UserPolicyRules(request.UserId, request.PermissionId, request.OrganizationContext))
        {
            if (model.InRole(request.UserId, RoleId.Superuser) ||
                model.InResourceRole(request.UserId, rule.RoleId, request.Resource))
            {
                yield return PolicyEffect.Allow;
            }
        }
    }
}