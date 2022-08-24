namespace Authorization.Sample.Services;

public interface ICurrentDateService
{
    DateTimeOffset UtcNow { get; }
}