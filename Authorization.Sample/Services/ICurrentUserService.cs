using Authorization.Sample.Implementation;

namespace Authorization.Sample.Services;

public interface ICurrentUserService
{
    long UserId { get; }
    
    OrganizationContext OrganizationContext { get; }
}