namespace Authorization.Sample.Services;

public interface IAuthorizationEnforcer
{
    Task<bool> Enforce();
    
    Task<bool> Enforce(string policy);
    
    Task<bool> Enforce(object resource);
    
    Task<bool> Enforce(string policy, object resource);
    
    Task<IQueryable<T>> EnforceQueryable<T>(IQueryable<T> resource);
    
    Task<IQueryable<T>> EnforceQueryable<T>(string policy, IQueryable<T> resource);
}