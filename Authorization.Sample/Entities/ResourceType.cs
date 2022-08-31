using LinqToDB;
using LinqToDB.Mapping;

namespace Authorization.Sample.Entities;

[Table(Name = "resource_type")]
public class ResourceType
{
    [Column(Name = "id", DataType = DataType.Int64, IsPrimaryKey = true, CanBeNull = false)]
    public ResourceTypeId Id { get; set; }

    [Column(Name = "name", DataType = DataType.VarChar, Length = 255)]
    public string Name { get; set; }
}