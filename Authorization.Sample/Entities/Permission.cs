using LinqToDB;
using LinqToDB.Mapping;

namespace Authorization.Sample.Entities;

[Table(Name = "permissions")]
public class Permission
{
    [Column(Name = "id", DataType = DataType.Long, IsPrimaryKey = true, CanBeNull = false)]
    public PermissionId Id { get; set; }

    [Column(Name = "name", DataType = DataType.VarChar, Length = 255)]
    public string Name { get; set; }

    [Column(Name = "is_readonly", DataType = DataType.Boolean, CanBeNull = false)]
    public bool IsReadonly { get; set; }
}