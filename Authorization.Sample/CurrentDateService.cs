namespace Authorization.Sample;

public class CurrentDateService : ICurrentDateService
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}