using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class DocumentAuthorizationModel : ResourceAuthorizationModel
{
    public IQueryable<DocumentPolicyRule> DocumentPolicyRules { get; }

    public DocumentAuthorizationModel(
        IQueryable<ResourcePolicyRule> resourcePolicyRules, 
        IQueryable<RolePolicyRule> rolePolicyRules, 
        IQueryable<DocumentPolicyRule> documentPolicyRules,
        IQueryable<Permission> permissions) 
        : base(resourcePolicyRules, rolePolicyRules, permissions)
    {
        DocumentPolicyRules = documentPolicyRules;
    }

    public bool HasAnyDocumentAccess(long userId)
    {
        // user, any, any - супервизор
        // user, doc, any - имеет доступ ко всем типам документов
        return ResourcePolicyRules
            .Any(r => r.UserId == userId &&
                      (r.Resource == SecurableId.Document || r.Resource == SecurableId.Any) &&
                      (r.Action == PermissionId.Any));
    }
}