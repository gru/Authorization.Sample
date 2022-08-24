namespace Authorization.Sample.Implementation;

public interface ICurrentUserAuthorizationRequest
{
    public long UserId { get; set; }
}