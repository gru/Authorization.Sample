namespace Authorization.Sample.Implementation;

public abstract class Matcher<TRequest, TModel> : IMatcher<TRequest>
{
    private readonly IAuthorizationModelFactory<TModel> _modelFactory;

    protected Matcher(IAuthorizationModelFactory<TModel> modelFactory)
    {
        _modelFactory = modelFactory;
    }

    public IEnumerable<PolicyEffect> Match(TRequest request)
    {
        return Match(request, _modelFactory.PrepareModel());
    }

    protected abstract IEnumerable<PolicyEffect> Match(TRequest request, TModel model);
}