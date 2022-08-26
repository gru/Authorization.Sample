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
        if (model.InRole(request.UserId, RoleId.Superuser))
            return query;

        // supervisor должен получить все документы без фильтрации по типу и офису
        if (model.HasResourcePermission(request.UserId, SecurableId.Any, PermissionId.Any))
            return query;
        
        if (request.OrganizationContext != null)
        {
            query = query
                .Where(d => (d.BranchId == request.OrganizationContext.BranchId) &&
                            (d.OfficeId == request.OrganizationContext.OfficeId || request.OrganizationContext.OfficeId == null));
        }

        // если есть разрешение на ресурс, то нужно вернуть все документы без фильтрации по типу
        if (model.HasResourcePermission(request.UserId, SecurableId.Document, request.PermissionId))
            return query;
        
        // получаем разрещенные обекты
        var allowedDocumentTypes = model.UserAllowedDocumentTypes(request.UserId, request.PermissionId, request.OrganizationContext);

        query = query.Where(d => allowedDocumentTypes.Contains(d.DocumentTypeId));

        return query;
    }
}