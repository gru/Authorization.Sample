namespace Authorization.Sample.Implementation;

public class ResourceMatcher : Matcher<ResourceAuthorizationRequest, AuthorizationModel>
{
    public ResourceMatcher(
        IAuthorizationModelFactory<AuthorizationModel> modelFactory) 
        : base(modelFactory)
    {
    }

    protected override bool Match(ResourceAuthorizationRequest request, AuthorizationModel model)
    {
        return model.HasPermission(
            userId: request.UserId,
            securableId: request.SecurableId,
            permissionId: request.PermissionId,
            organizationContext: request.OrganizationContext);
    }
}