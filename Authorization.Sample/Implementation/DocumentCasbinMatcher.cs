using Casbin;

namespace Authorization.Sample.Implementation;

public class DocumentCasbinMatcher : Matcher<DocumentAuthorizationRequest, IEnforcer>
{
    public DocumentCasbinMatcher(IAuthorizationModelFactory<IEnforcer> modelFactory) : base(modelFactory)
    {
    }

    protected override IEnumerable<PolicyEffect> Match(DocumentAuthorizationRequest request, IEnforcer enforcer)
    {
        var sub = request.UserId.ToString();
        var obj = request.DocumentTypeId.ToString();
        var act = request.PermissionId.ToString();
        var ctx = request.OrganizationContext.ToCasbinString();

        var enforceContext = EnforceContext
            .Create(enforcer, policyType: "p2", matcherType: "m2");

        if (enforcer.Enforce(enforceContext, sub, obj, act, ctx))
            yield return PolicyEffect.Allow;
    }
}