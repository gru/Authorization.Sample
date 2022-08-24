namespace Authorization.Sample.Implementation;

public interface IMatcher<in TRequest>
{
    IEnumerable<PolicyEffect> Match(TRequest request);
}