namespace Authorization.Sample.Implementation;

public class ResourceMatcher : Matcher<ResourceAuthorizationRequest, AuthorizationModel>
{
    public ResourceMatcher(
        IAuthorizationModelFactory<AuthorizationModel> modelFactory) 
        : base(modelFactory)
    {
    }

    protected override IEnumerable<PolicyEffect> Match(ResourceAuthorizationRequest request, AuthorizationModel model)
    {
        if (model.HasPermission(request.UserId, request.SecurableId, request.PermissionId, request.OrganizationContext))
            yield return PolicyEffect.Allow;
    }
}