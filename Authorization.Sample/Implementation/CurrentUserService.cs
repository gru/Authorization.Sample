using Authorization.Sample.Services;

namespace Authorization.Sample.Implementation;

public class CurrentUserService : ICurrentUserService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public CurrentUserService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public long UserId
    {
        get
        {
            var context = _httpContextAccessor.HttpContext;
            if (context?.User.Identity?.Name != null && int.TryParse(context.User.Identity.Name, out var userId))
                return userId;

            return 0;
        }
    }

    public OrganizationContext OrganizationContext
    {
        get
        {
            var query = _httpContextAccessor.HttpContext?.Request.Query;
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
                    
                    return new OrganizationContext(branchId, regionalOfficeId, officeId);
                }
            }

            return null;
        }
    }
}