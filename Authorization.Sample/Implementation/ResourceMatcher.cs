using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class ResourceMatcher : Matcher<ResourceAuthorizationRequest, AuthorizationModel>
{
    public ResourceMatcher(
        IAuthorizationModelFactory<AuthorizationModel> modelFactory) 
        : base(modelFactory)
    {
    }

    protected override IEnumerable<PolicyEffect> Match(ResourceAuthorizationRequest request, AuthorizationModel model)
    {
        foreach (var rule in model.UserPolicyRules(request.UserId, request.PermissionId, request.OrganizationContext))
        {
            if (model.InResourceRole(request.UserId, rule.RoleId, request.SecurableId, rule.PermissionId))
                yield return PolicyEffect.Allow;
        }
    }
}