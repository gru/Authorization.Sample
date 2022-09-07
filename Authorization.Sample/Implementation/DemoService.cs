using Authorization.Sample.Services;

namespace Authorization.Sample.Implementation;

public class DemoService : IDemoService
{
    public DemoService(bool enabled)
    {
        IsDemoModeActive = enabled;
    }

    public bool IsDemoModeActive { get; }
}