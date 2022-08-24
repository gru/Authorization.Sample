namespace Authorization.Sample.Implementation;

public interface IOrganizationContextRule
{
    long? BranchId { get; }
    
    long? RegionalOfficeId { get; }
    
    long? OfficeId { get; }
}