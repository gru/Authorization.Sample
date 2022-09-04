using Microsoft.AspNetCore.Authorization;

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
        var (branch, regOffice, office) = GetOrganizationContext();
        var input = new OpaInput
        {
            Subject = subject,
            Action = requirement.Operation,
            Object = requirement.Resource,
            Extensions = new Dictionary<string, object>
            {
                ["orgContext"] = new
                {
                    branch = OrgContextHelpers.ToOrgContextValue(branch),
                    regOffice = OrgContextHelpers.ToOrgContextValue(regOffice),
                    office = OrgContextHelpers.ToOrgContextValue(office),
                }
            }
        };

        var result = await _opaClient.Evaluate(policy, input);
        if (result) context.Succeed(requirement);
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