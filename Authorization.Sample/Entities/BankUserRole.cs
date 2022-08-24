using LinqToDB;
using LinqToDB.Mapping;

namespace Authorization.Sample.Entities;

[Table(Name = "bankuser_roles")]
public class BankUserRole
{
    [Column(Name = "bankuser_id", DataType = DataType.Long, IsPrimaryKey = true, CanBeNull = false)]
    public BankUserId BankUserId { get; set; }
    
    [Column(Name = "role_id", DataType = DataType.Long, IsPrimaryKey = true, CanBeNull = false)]
    public RoleId RoleId { get; set; }
    
    [Column(Name = "branch_id", DataType = DataType.Long, CanBeNull = true)]
    public long? BranchId { get; set; }
    
    [Column(Name = "regional_office_id", DataType = DataType.Long, CanBeNull = true)]
    public long? RegionalOfficeId { get; set; }
    
    [Column(Name = "office_id", DataType = DataType.Long, CanBeNull = true)]
    public long? OfficeId { get; set; }

    [Column(Name = "end_date", DataType = DataType.DateTimeOffset, CanBeNull = true)]
    public DateTimeOffset? EndDate { get; set; }
}