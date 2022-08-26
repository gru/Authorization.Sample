using Authorization.Sample.Entities;
using Authorization.Sample.Services;

namespace Authorization.Sample.Implementation;

public class AuthorizationModelFactory : IAuthorizationModelFactory<AuthorizationModel>
{
    private readonly DataContext _context;
    private readonly IDemoService _demoService;
    private readonly ICurrentDateService _dateService;

    public AuthorizationModelFactory(
        DataContext context, IDemoService demoService, ICurrentDateService dateService)
    {
        _context = context;
        _demoService = demoService;
        _dateService = dateService;
    }
    
    public AuthorizationModel PrepareModel()
    {
        var options = new AuthorizationModelOptions(_demoService.IsDemoModeActive);
        var model = new AuthorizationModel(_context, options, _dateService);
        return model;
    }
}