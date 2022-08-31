using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class DocumentFilter : Filter<Document, DefaultFilterRequest, AuthorizationModel>
{
    public DocumentFilter(IAuthorizationModelFactory<AuthorizationModel> modelFactory) 
        : base(modelFactory)
    {
    }
    
    protected override IQueryable<Document> Apply(IQueryable<Document> query, DefaultFilterRequest request, AuthorizationModel model)
    {
        // supervisor должен получить все документы без фильтрации по типу и офису
        if (model.HasPermission(request.UserId, SecurableId.Any, PermissionId.Any, null))
            return query;
        
        if (request.OrganizationContext != null)
        {
            query = query
                .Where(d => (d.BranchId == request.OrganizationContext.BranchId) &&
                            (d.OfficeId == request.OrganizationContext.OfficeId || request.OrganizationContext.OfficeId == null));
        }

        // получаем разрещенные обекты
        var allowedDocumentTypes = model.UserAllowedDocumentTypes(request.UserId, request.PermissionId, request.OrganizationContext);

        query = query.Where(d => allowedDocumentTypes.Contains(d.DocumentTypeId));

        return query;
    }
}