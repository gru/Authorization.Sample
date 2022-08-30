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
        var sub = request.UserId.ToString();
        var act = request.PermissionId.ToString();
        var ctx = request.OrganizationContext.ToCasbinString();

        var roles = enforcer.GetImplicitRolesForUser(sub, ctx);
        var allowedDocumentTypes = enforcer.GetFilteredNamedPolicy("p2", 0, roles.ToArray())
            .Where(p => p.ElementAt(2) == act)
            .Select(p => Enum.Parse<DocumentTypeId>(p.ElementAt(1)));
        
        query = query.Where(d => allowedDocumentTypes.Contains(d.DocumentTypeId));

        return query;
    }
}