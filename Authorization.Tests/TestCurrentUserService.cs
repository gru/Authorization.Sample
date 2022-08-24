using Authorization.Sample.Entities;
using Authorization.Sample.Implementation;
using Authorization.Sample.Services;

namespace Authorization.Tests;

public class TestCurrentUserService : ICurrentUserService
{
    public TestCurrentUserService(BankUserId userId, OrganizationContext organizationContext = null)
    {
        UserId = (long) userId;
        OrganizationContext = organizationContext;
    }

    public long UserId { get; }
    
    public OrganizationContext OrganizationContext { get; }
}