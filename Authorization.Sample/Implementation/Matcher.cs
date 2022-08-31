namespace Authorization.Sample.Implementation;

public abstract class Matcher<TRequest, TModel> : IMatcher<TRequest>
{
    private readonly IAuthorizationModelFactory<TModel> _modelFactory;

    protected Matcher(IAuthorizationModelFactory<TModel> modelFactory)
    {
        _modelFactory = modelFactory;
    }

    public bool Match(TRequest request)
    {
        return Match(request, _modelFactory.PrepareModel());
    }

    protected abstract bool Match(TRequest request, TModel model);
}