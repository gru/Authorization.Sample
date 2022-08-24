namespace Authorization.Sample.Services;

public class DemoService : IDemoService
{
    public DemoService(bool enabled)
    {
        IsDemoModeActive = enabled;
    }

    public bool IsDemoModeActive { get; }
}