using Authorization.Sample;
using Authorization.Tests.Entities;

namespace Authorization.Tests;

public class TestUserService : ICurrentUserService
{
    public TestUserService(BankUserId userId)
    {
        UserId = (long) userId;
    }

    public long UserId { get; }
}