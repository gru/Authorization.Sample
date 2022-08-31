using Casbin;

namespace Authorization.Sample.Implementation;

public class DocumentCasbinMatcher : Matcher<DocumentAuthorizationRequest, IEnforcer>
{
    public DocumentCasbinMatcher(IAuthorizationModelFactory<IEnforcer> modelFactory) : base(modelFactory)
    {
    }

    protected override bool Match(DocumentAuthorizationRequest request, IEnforcer enforcer)
    {
        var sub = request.UserId.ToUserString();
        var obj = request.DocumentTypeId.ToString();
        var act = request.PermissionId.ToString();
        var ctx = request.OrganizationContext.ToCasbinString();
        const string res = "DocumentType";
        
        return enforcer.Enforce(sub, res, obj, act, ctx);
    }
}