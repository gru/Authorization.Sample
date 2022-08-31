using Authorization.Sample.Entities;
using Casbin;

namespace Authorization.Sample.Implementation;

public class DocumentationFileCategoryFilter : Filter<DocumentationFileCategory, DefaultFilterRequest, IEnforcer>
{
    public DocumentationFileCategoryFilter(IAuthorizationModelFactory<IEnforcer> modelFactory) 
        : base(modelFactory)
    {
    }

    protected override IQueryable<DocumentationFileCategory> Apply(IQueryable<DocumentationFileCategory> query, DefaultFilterRequest request, IEnforcer enforcer)
    {
        var sub = request.UserId.ToString();
        const string obj = "*";
        const string act = "*";
        var ctx = request.OrganizationContext.ToCasbinString();

        // для супервизора фильтр не применяем
        if (enforcer.Enforce(sub, obj, act, ctx))
            return query;
        
        // для клиетских пользователей возвращать DocumentationFileCategoryType.All, DocumentationFileCategoryType.Client 
        // для банковских пользователей возвращать DocumentationFileCategoryType.All, DocumentationFileCategoryType.Bank
        // в приложении только банковские пользователи

        var allowedCategoryTypes = new[] { DocumentationFileCategoryType.All, DocumentationFileCategoryType.Bank };

        return query.Where(c => allowedCategoryTypes.Contains(c.CategoryType));
    }
}