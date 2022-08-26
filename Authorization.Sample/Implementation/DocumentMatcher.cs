using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class DocumentMatcher : Matcher<DocumentAuthorizationRequest, AuthorizationModel>
{
    public DocumentMatcher(IAuthorizationModelFactory<AuthorizationModel> modelFactory) 
        : base(modelFactory)
    {
    }

    protected override IEnumerable<PolicyEffect> Match(DocumentAuthorizationRequest request, AuthorizationModel model)
    {
        foreach (var rule in model.UserPolicyRules(request.UserId, request.PermissionId, request.OrganizationContext))
        {
            if (model.InRole(request.UserId, RoleId.Superuser) ||
                model.InDocumentTypeRole(request.UserId, rule.RoleId, request.DocumentTypeId) ||
                model.InResourceRole(request.UserId, rule.RoleId, SecurableId.Document, rule.PermissionId))
            {
                yield return PolicyEffect.Allow;
            }
        }
    }
}