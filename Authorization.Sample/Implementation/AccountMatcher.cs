using Authorization.Sample.Services;

namespace Authorization.Sample.Implementation;

public class AccountMatcher : Matcher<AccountAuthorizationRequest, AccountAuthorizationModel>
{
    private readonly IDemoService _demoService;

    public AccountMatcher(IAuthorizationModelFactory<AccountAuthorizationModel> modelFactory, IDemoService demoService) 
        : base(modelFactory)
    {
        _demoService = demoService;
    }

    protected override IEnumerable<PolicyEffect> Match(AccountAuthorizationRequest request, AccountAuthorizationModel model)
    {
        if (_demoService.IsDemoModeActive && !model.IsReadOnlyPermission(request.PermissionId))
        {
            yield return PolicyEffect.Deny;
        }
        else if (model.IsSuperuser(request.UserId) || model.HasAnyAccountAccess(request.UserId))
        {
            yield return PolicyEffect.Allow;
        }
        else
        {
            var groups = model.GL2Lookup[request.GL2];
            
            var query = model.AccountPolicyRules
                .Where(r => r.UserId == request.UserId &&
                            r.PermissionId == request.PermissionId &&
                            groups.Contains(r.GL2GroupId));

            query = model.ApplyOrganizationContextFilter(query, request.OrganizationContext);
            
            if (query.Any())
                yield return PolicyEffect.Allow;
        }
    }
}