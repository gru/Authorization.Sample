namespace Authorization.Sample.Entities;

public class DocumentTypeRolePermission
{
    public RoleId RoleId { get; set; }

    public PermissionId PermissionId { get; set; }

    public DocumentTypeId DocumentTypeId { get; set; }
}