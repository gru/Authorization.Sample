using Authorization.Sample.Entities;
using Casbin;

namespace Authorization.Sample.Implementation;

public class DocumentCasbinFilter : Filter<Document, DefaultFilterRequest, IEnforcer>
{
    public DocumentCasbinFilter(IAuthorizationModelFactory<IEnforcer> modelFactory)
        : base(modelFactory)
    {
    }

    protected override IQueryable<Document> Apply(IQueryable<Document> query, DefaultFilterRequest request, IEnforcer enforcer)
    {
        var sub = request.UserId.ToUserString();
        var act = request.PermissionId.ToString();
        var ctx = request.OrganizationContext.ToCasbinString();

        const string documentTypeSection = "p2";
        
        var documentTypeAssertion = enforcer.PolicyManager
            .Sections[PermConstants.DefaultPolicyType][documentTypeSection];
        
        var subIndex = documentTypeAssertion.Tokens["sub"];
        var actIndex = documentTypeAssertion.Tokens["act"];
        var typeIndex = documentTypeAssertion.Tokens["type"];
        
        var roles = enforcer.GetImplicitRolesForUser(sub, ctx);
        var allowedDocumentTypes = enforcer
            .GetFilteredNamedPolicy(documentTypeSection, subIndex, roles.ToArray())
            .Where(p => p.ElementAt(actIndex) == act)
            .Select(p => Enum.Parse<DocumentTypeId>(p.ElementAt(typeIndex)));
        
        query = query.Where(d => allowedDocumentTypes.Contains(d.DocumentTypeId));

        return query;
    }
}