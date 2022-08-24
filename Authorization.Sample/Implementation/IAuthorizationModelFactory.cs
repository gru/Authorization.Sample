namespace Authorization.Sample.Implementation;

public interface IAuthorizationModelFactory<out TModel>
{
    public TModel PrepareModel();
}