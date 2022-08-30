using Casbin;

namespace Authorization.Sample.Implementation;

public class ResourceCasbinMatcher : Matcher<ResourceAuthorizationRequest, IEnforcer>
{
    public ResourceCasbinMatcher(IAuthorizationModelFactory<IEnforcer> modelFactory) 
        : base(modelFactory)
    {
    }

    protected override IEnumerable<PolicyEffect> Match(ResourceAuthorizationRequest request, IEnforcer enforcer)
    {
        var sub = request.UserId.ToString();
        var obj = request.SecurableId.ToString();
        var act = request.PermissionId.ToString();
        var ctx = request.OrganizationContext.ToCasbinString();

        if (enforcer.Enforce(sub, obj, act, ctx))
            yield return PolicyEffect.Allow;
    }
}