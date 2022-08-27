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
        if (model.InDocumentTypeRole(request.UserId, request.DocumentTypeId, request.PermissionId, request.OrganizationContext) ||
            model.InResourceRole(request.UserId, SecurableId.Document, request.PermissionId, request.OrganizationContext))
        {
            yield return PolicyEffect.Allow;
        }
    }
}