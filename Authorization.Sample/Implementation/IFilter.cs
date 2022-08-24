namespace Authorization.Sample.Implementation;

public interface IFilter<T, in TContext>
{
    IQueryable<T> Apply(IQueryable<T> query, TContext request);
}