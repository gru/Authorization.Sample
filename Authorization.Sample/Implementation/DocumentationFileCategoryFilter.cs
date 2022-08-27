using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class DocumentationFileCategoryFilter : Filter<DocumentationFileCategory, DefaultFilterRequest, AuthorizationModel>
{
    public DocumentationFileCategoryFilter(IAuthorizationModelFactory<AuthorizationModel> modelFactory) 
        : base(modelFactory)
    {
    }

    protected override IQueryable<DocumentationFileCategory> Apply(IQueryable<DocumentationFileCategory> query, DefaultFilterRequest request, AuthorizationModel model)
    {
        // для супервизора фильтр не применяем
        if (model.InResourceRole(request.UserId, SecurableId.Any, PermissionId.Any, request.OrganizationContext))
            return query;
        
        // для клиетских пользователей возвращать DocumentationFileCategoryType.All, DocumentationFileCategoryType.Client 
        // для банковских пользователей возвращать DocumentationFileCategoryType.All, DocumentationFileCategoryType.Bank
        // в приложении только банковские пользователи

        var allowedCategoryTypes = new[] { DocumentationFileCategoryType.All, DocumentationFileCategoryType.Bank };

        return query.Where(c => allowedCategoryTypes.Contains(c.CategoryType));
    }
}