using LinqToDB;
using LinqToDB.Mapping;

namespace Authorization.Sample.Entities;

[Table(Name = "document_type_role_permissions")]
public class DocumentTypeRolePermission
{
    [Column(Name = "id", DataType = DataType.Int32, IsPrimaryKey = true, IsIdentity = true, CanBeNull = false)]
    public long Id { get; set; }
    
    [Column(Name = "role_id", DataType = DataType.Long, CanBeNull = false)]
    public RoleId RoleId { get; set; }
    
    [Column(Name = "permission_id", DataType = DataType.Long, CanBeNull = false)]
    public PermissionId PermissionId { get; set; }

    [Column(Name = "document_type_id", DataType = DataType.Long, CanBeNull = false)]
    public DocumentTypeId DocumentTypeId { get; set; }
    
    [Column(Name = "is_readonly", DataType = DataType.Boolean, CanBeNull = false)]
    public bool IsReadonly { get; set; }
}