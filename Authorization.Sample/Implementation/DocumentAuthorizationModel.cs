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
}