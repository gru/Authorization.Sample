using Authorization.Sample.Services;

namespace Authorization.Sample.Implementation;

public class CurrentDateService : ICurrentDateService
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}