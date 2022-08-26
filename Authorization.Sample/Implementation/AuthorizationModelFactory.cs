using Authorization.Sample.Entities;
using Authorization.Sample.Services;

namespace Authorization.Sample.Implementation;

public class AuthorizationModelFactory : IAuthorizationModelFactory<AuthorizationModel>
{
    private readonly DataContext _context;
    private readonly ICurrentDateService _dateService;

    public AuthorizationModelFactory(DataContext context, ICurrentDateService dateService)
    {
        _context = context;
        _dateService = dateService;
    }
    
    public AuthorizationModel PrepareModel()
    {
        var model = new AuthorizationModel(_context, _dateService);
        return model;
    }
}