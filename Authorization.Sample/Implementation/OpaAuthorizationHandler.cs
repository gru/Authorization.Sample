using Microsoft.AspNetCore.Authorization;
using static Authorization.Sample.Implementation.OrgContextHelpers;

namespace Authorization.Sample.Implementation;

public class OpaAuthorizationHandler : AuthorizationHandler<OpaRequirement>
{
    private readonly IOpaClient _opaClient;
    private readonly IHttpContextAccessor _contextAccessor;

    public OpaAuthorizationHandler(IOpaClient opaClient, IHttpContextAccessor contextAccessor)
    {
        _opaClient = opaClient;
        _contextAccessor = contextAccessor;
    }

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, OpaRequirement requirement)
    {
        var policy = requirement.GetPolicy();
        var subject = OpaInputUser.FromPrincipal(context.User);
        var (branchId, regionalOfficeId, officeId) = GetOrganizationContext();
        var input = new OpaInput
        {
            Subject = subject,
            PermissionId = requirement.PermissionId,
            SecurableId = requirement.SecurableId,
            Extensions = new Dictionary<string, object>
            {
                [nameof(OrganizationContext)] = new
                {
                    BranchId = ToOrgContextValue(branchId),
                    RegionalOfficeId = ToOrgContextValue(regionalOfficeId),
                    OfficeId = ToOrgContextValue(officeId),
                }
            }
        };

        if (context.Resource != null && context.Resource is not HttpContext)
        {
            input.Extensions["Resource"] = context.Resource;
        }
        
        var result = await _opaClient.Evaluate(policy, input);
        if (result)
        {
            context.Succeed(requirement);
        }
    }

    private (long?, long?, long?) GetOrganizationContext()
    {
        var query = _contextAccessor.HttpContext?.Request.Query;
        if (query != null)
        {
            if (query.TryGetValue("branchId", out var branchIdString) && 
                long.TryParse(branchIdString, out var branchId))
            {
                long? regionalOfficeId = 
                    query.TryGetValue("regionalOfficeId", out var regionalOfficeIdString) && long.TryParse(regionalOfficeIdString, out var regionalOfficeIdValue)
                        ? regionalOfficeIdValue
                        : null;

                long? officeId = 
                    query.TryGetValue("regionalOfficeId", out var officeIdString) && long.TryParse(officeIdString, out var officeIdValue)
                        ? officeIdValue
                        : null;

                return (branchId, regionalOfficeId, officeId);
            }
        }

        return (null, null, null);
    }
}