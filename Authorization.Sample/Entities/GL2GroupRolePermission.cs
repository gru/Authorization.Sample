using LinqToDB;
using LinqToDB.Mapping;

namespace Authorization.Sample.Entities;

[Table(Name = "gl2_groups_role_permissions")]
public class GL2GroupRolePermission
{
    [Column(Name = "id", DataType = DataType.Int32, IsPrimaryKey = true, IsIdentity = true, CanBeNull = false)]
    public long Id { get; set; }
    
    [Column(Name = "role_id", DataType = DataType.Long, CanBeNull = false)]
    public RoleId RoleId { get; set; }

    [Column(Name = "permission_id", DataType = DataType.Long, CanBeNull = false)]
    public PermissionId PermissionId { get; set; }
    
    [Column(Name = "gl2_group_id", DataType = DataType.Long, CanBeNull = false)]
    public long GL2GroupId  { get; set; }
}