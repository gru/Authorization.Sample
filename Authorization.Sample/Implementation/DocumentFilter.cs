using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class DocumentFilter : Filter<Document, DocumentFilterRequest, AuthorizationModel>
{
    public DocumentFilter(IAuthorizationModelFactory<AuthorizationModel> modelFactory) 
        : base(modelFactory)
    {
    }
    
    protected override IQueryable<Document> Apply(IQueryable<Document> query, DocumentFilterRequest request, AuthorizationModel model)
    {
        // supervisor должен получить все документы без фильтрации по типу и офису
        if (model.InResourceRole(request.UserId, SecurableId.Any, PermissionId.Any, null))
            return query;
        
        if (request.OrganizationContext != null)
        {
            query = query
                .Where(d => (d.BranchId == request.OrganizationContext.BranchId) &&
                            (d.OfficeId == request.OrganizationContext.OfficeId || request.OrganizationContext.OfficeId == null));
        }

        // если есть разрешение на ресурс, то нужно вернуть все документы без фильтрации по типу
        if (model.InResourceRole(request.UserId, SecurableId.Document, request.PermissionId, request.OrganizationContext))
            return query;
        
        // получаем разрещенные обекты
        var allowedDocumentTypes = model.UserAllowedDocumentTypes(request.UserId, request.PermissionId, request.OrganizationContext);

        query = query.Where(d => allowedDocumentTypes.Contains(d.DocumentTypeId));

        return query;
    }
}