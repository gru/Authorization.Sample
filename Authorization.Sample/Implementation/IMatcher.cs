namespace Authorization.Sample.Implementation;

public interface IMatcher<in TRequest>
{
    bool Match(TRequest request);
}