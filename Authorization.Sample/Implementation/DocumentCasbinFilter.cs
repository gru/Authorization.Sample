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
        const string res = "DocumentType";

        if (enforcer.Enforce(sub, "*", "*", "*", OrganizationContext.Empty.ToCasbinString()))
            return query;
        
        if (request.OrganizationContext != null)
        {
            query = query
                .Where(d => (d.BranchId == request.OrganizationContext.BranchId) &&
                            (d.OfficeId == request.OrganizationContext.OfficeId || request.OrganizationContext.OfficeId == null));
        }
        
        var documentTypeAssertion = enforcer.PolicyManager
            .Sections[PermConstants.DefaultPolicyType][PermConstants.DefaultPolicyType];
        
        var subIndex = documentTypeAssertion.Tokens["sub"];
        var actIndex = documentTypeAssertion.Tokens["act"];
        var objIndex = documentTypeAssertion.Tokens["obj"];
        var resIndex = documentTypeAssertion.Tokens["res"];
        
        var roles = enforcer.GetRolesForUser(sub, ctx).ToArray();
        if (roles.Length == 0) return query.Where(d => false);
        
        var allowedDocumentTypes = enforcer
            .GetFilteredNamedPolicy(PermConstants.DefaultPolicyType, subIndex, roles.ToArray())
            .Where(p => p.ElementAt(actIndex) == act && p.ElementAt(resIndex) == res)
            .Select(p => Enum.Parse<DocumentTypeId>(p.ElementAt(objIndex)));
    
        query = query.Where(d => allowedDocumentTypes.Contains(d.DocumentTypeId));

        return query;
    }
}