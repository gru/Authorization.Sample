using LinqToDB;
using LinqToDB.Mapping;

namespace Authorization.Sample.Entities;

[Table(Name = "role_permissions")]
public class RolePermission
{
    [Column(Name = "id", DataType = DataType.Int32, IsPrimaryKey = true, IsIdentity = true, CanBeNull = false)]
    public long Id { get; set; }
    
    [Column(Name = "role_id", DataType = DataType.Long, CanBeNull = false)]
    public RoleId RoleId { get; set; }
    
    [Column(Name = "securable_id", DataType = DataType.Long, CanBeNull = false)]
    public SecurableId SecurableId { get; set; }

    [Column(Name = "resource_type_id", DataType = DataType.Long, CanBeNull = true)]
    public ResourceTypeId? ResourceTypeId { get; set; }

    [Column(Name = "resource_id", DataType = DataType.Long, CanBeNull = true)]
    public long? ResourceId { get; set; }
    
    [Column(Name = "permission_id", DataType = DataType.Long, CanBeNull = false)]
    public PermissionId PermissionId { get; set; }
}