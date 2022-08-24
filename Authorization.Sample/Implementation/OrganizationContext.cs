namespace Authorization.Sample.Implementation;

public class OrganizationContext
{
    public OrganizationContext(long branchId)
    {
        BranchId = branchId;
    }

    public OrganizationContext(long branchId, long regionalOfficeId)
        : this(branchId)
    {
        RegionalOfficeId = regionalOfficeId;
    }

    public OrganizationContext(long branchId, long? regionalOfficeId, long officeId)
    {
        BranchId = branchId;
        RegionalOfficeId = regionalOfficeId;
        OfficeId = officeId;
    }

    public long BranchId { get; }
    
    public long? RegionalOfficeId { get; }
    
    public long? OfficeId { get; }
}