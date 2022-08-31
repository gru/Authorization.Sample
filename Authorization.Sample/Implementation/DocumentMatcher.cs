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
        if (model.HasPermission(request.UserId, SecurableId.Document, ResourceTypeId.DocumentType, (long) request.DocumentTypeId, request.PermissionId, request.OrganizationContext))
        {
            yield return PolicyEffect.Allow;
        }
    }
}