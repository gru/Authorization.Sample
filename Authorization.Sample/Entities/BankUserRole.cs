namespace Authorization.Sample.Entities;

public class BankUserRole
{
    public BankUserId BankUserId { get; set; }
    
    public RoleId RoleId { get; set; }
    
    public long? BranchId { get; set; }
    
    public long? RegionalOfficeId { get; set; }
    
    public long? OfficeId { get; set; }

    public DateTimeOffset? EndDate { get; set; }
}