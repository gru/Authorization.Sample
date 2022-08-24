namespace Authorization.Sample.Services;

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
}