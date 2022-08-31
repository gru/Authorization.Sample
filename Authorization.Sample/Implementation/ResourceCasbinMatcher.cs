using Casbin;

namespace Authorization.Sample.Implementation;

public class ResourceCasbinMatcher : Matcher<ResourceAuthorizationRequest, IEnforcer>
{
    public ResourceCasbinMatcher(IAuthorizationModelFactory<IEnforcer> modelFactory) 
        : base(modelFactory)
    {
    }

    protected override bool Match(ResourceAuthorizationRequest request, IEnforcer enforcer)
    {
        var sub = request.UserId.ToUserString();
        var obj = request.SecurableId.ToString();
        var act = request.PermissionId.ToString();
        var ctx = request.OrganizationContext.ToCasbinString();

        return enforcer.Enforce(sub, obj, act, ctx);
    }
}