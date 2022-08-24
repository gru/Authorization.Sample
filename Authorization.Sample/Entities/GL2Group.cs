using LinqToDB;
using LinqToDB.Mapping;

namespace Authorization.Sample.Entities;

[Table(Name = "gl2_groups")]
public class GL2Group
{
    [Column(Name = "id", DataType = DataType.Int32, IsPrimaryKey = true, IsIdentity = true, CanBeNull = false)]
    public long Id { get; set; }
    
    [Column(Name = "gl2_group_id", DataType = DataType.Long, CanBeNull = false)]
    public long GL2GroupId { get; set; }
    
    [Column(Name = "gl2", DataType = DataType.VarChar, Length = 5, CanBeNull = false)]
    public string GL2 { get; set; }
}