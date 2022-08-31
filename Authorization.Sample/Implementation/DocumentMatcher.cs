using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class DocumentMatcher : Matcher<DocumentAuthorizationRequest, AuthorizationModel>
{
    public DocumentMatcher(IAuthorizationModelFactory<AuthorizationModel> modelFactory) 
        : base(modelFactory)
    {
    }

    protected override bool Match(DocumentAuthorizationRequest request, AuthorizationModel model)
    {
        return model.HasPermission(
            userId: request.UserId,
            securableId: SecurableId.Document,
            resourceTypeId: ResourceTypeId.DocumentType,
            resourceId: (long) request.DocumentTypeId,
            permissionId: request.PermissionId,
            organizationContext: request.OrganizationContext);
    }
}