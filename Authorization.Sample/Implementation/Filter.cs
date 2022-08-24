namespace Authorization.Sample.Implementation;

public abstract class Filter<T, TContext, TModel> : IFilter<T, TContext>
{
    private readonly IAuthorizationModelFactory<TModel> _modelFactory;

    protected Filter(IAuthorizationModelFactory<TModel> modelFactory)
    {
        _modelFactory = modelFactory;
    }

    public IQueryable<T> Apply(IQueryable<T> query, TContext request)
    {
        return Apply(query, request, _modelFactory.PrepareModel());
    }

    protected abstract IQueryable<T> Apply(IQueryable<T> query, TContext request, TModel model);
}