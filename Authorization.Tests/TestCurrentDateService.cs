using System;
using Authorization.Sample.Services;

namespace Authorization.Tests;

public class TestCurrentDateService : ICurrentDateService
{
    public TestCurrentDateService(DateTimeOffset utcNow)
    {
        UtcNow = utcNow;
    }

    public DateTimeOffset UtcNow { get; }
}