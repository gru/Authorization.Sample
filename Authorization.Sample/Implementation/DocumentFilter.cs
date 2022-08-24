using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class DocumentFilter : Filter<Document, DocumentFilterRequest, DocumentAuthorizationModel>
{
    public DocumentFilter(IAuthorizationModelFactory<DocumentAuthorizationModel> modelFactory) 
        : base(modelFactory)
    {
    }
    
    protected override IQueryable<Document> Apply(IQueryable<Document> query, DocumentFilterRequest request, DocumentAuthorizationModel model)
    {
        if (model.HasAnyDocumentAccess(request.UserId))
            return query;
        
        if (request.OrganizationContext != null)
        {
            query = query
                .Where(d => (d.BranchId == request.OrganizationContext.BranchId) &&
                            (d.OfficeId == request.OrganizationContext.OfficeId || request.OrganizationContext.OfficeId == null));
        }

        var rules = model.DocumentPolicyRules
            .Where(r => r.UserId == request.UserId &&
                        (r.PermissionId == PermissionId.Any || r.PermissionId == request.PermissionId));

        rules = model.ApplyOrganizationContextFilter(rules, request.OrganizationContext);
        
        var resultQuery = query
            .Join(rules,
                d => d.DocumentTypeId,
                r => r.DocumentTypeId,
                (d, r) => new { Document = d, Rule = r })
            .Select(pair => pair.Document);

        return resultQuery;
    }
}