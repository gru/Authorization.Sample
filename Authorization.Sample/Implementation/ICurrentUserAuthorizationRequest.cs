namespace Authorization.Sample.Implementation;

public interface ICurrentUserAuthorizationRequest
{
    public long UserId { get; set; }
    
    public OrganizationContext OrganizationContext { get; set; }
}