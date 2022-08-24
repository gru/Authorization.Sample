namespace Authorization.Sample.Implementation;

public class ResourcePermissionMatcher : Matcher<ResourceAuthorizationRequest, ResourceAuthorizationModel>
{
    public ResourcePermissionMatcher(IAuthorizationModelFactory<ResourceAuthorizationModel> modelFactory) 
        : base(modelFactory)
    {
    }

    protected override IEnumerable<PolicyEffect> Match(ResourceAuthorizationRequest request, ResourceAuthorizationModel model)
    {
        if (model.IsSuperuser(request.UserId))
            yield return PolicyEffect.Allow;

        if (model.HasPermission(request.UserId, request.Resource, request.Action, request.OrganizationContext))
            yield return PolicyEffect.Allow;
    }
}