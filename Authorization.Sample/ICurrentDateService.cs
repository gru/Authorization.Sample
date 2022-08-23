namespace Authorization.Sample;

public interface ICurrentDateService
{
    DateTimeOffset UtcNow { get; }
}