using Authorization.Sample.Entities;
using Authorization.Sample.Services;

namespace Authorization.Tests;

public class TestCurrentUserService : ICurrentUserService
{
    public TestCurrentUserService(BankUserId userId)
    {
        UserId = (long) userId;
    }

    public long UserId { get; }
}