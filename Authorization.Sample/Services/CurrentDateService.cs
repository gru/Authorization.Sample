namespace Authorization.Sample.Services;

public class CurrentDateService : ICurrentDateService
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}