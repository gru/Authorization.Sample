using Authorization.Sample.Services;

namespace Authorization.Sample.Implementation;

public class ResourcePermissionMatcher : Matcher<ResourceAuthorizationRequest, ResourceAuthorizationModel>
{
    private readonly IDemoService _demoService;

    public ResourcePermissionMatcher(
        IAuthorizationModelFactory<ResourceAuthorizationModel> modelFactory, IDemoService demoService) 
        : base(modelFactory)
    {
        _demoService = demoService;
    }

    protected override IEnumerable<PolicyEffect> Match(ResourceAuthorizationRequest request, ResourceAuthorizationModel model)
    {
        if (_demoService.IsDemoModeActive && !model.IsReadOnlyPermission(request.PermissionId))
        {
            yield return PolicyEffect.Deny;
        }
        else
        {
            if (model.IsSuperuser(request.UserId))
                yield return PolicyEffect.Allow;

            if (model.HasPermission(request.UserId, request.Resource, request.PermissionId, request.OrganizationContext))
                yield return PolicyEffect.Allow;
        }
    }
}