using LinqToDB;
using LinqToDB.Mapping;

namespace Authorization.Sample.Entities;

[Table(Name = "securables")]
public class Securable
{
    [Column(Name = "id", DataType = DataType.Long, IsPrimaryKey = true, CanBeNull = false)]
    public SecurableId Id { get; set; }

    [Column(Name = "name", DataType = DataType.VarChar, Length = 255)]
    public string Name { get; set; }
}