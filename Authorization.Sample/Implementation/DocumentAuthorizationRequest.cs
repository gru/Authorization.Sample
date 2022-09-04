using Authorization.Sample.Entities;

namespace Authorization.Sample.Implementation;

public class DocumentAuthorizationRequest
{
    public DocumentAuthorizationRequest(Document document, PermissionId permissionId)
    {
        PermissionId = permissionId;
        DocumentTypeId = document.DocumentTypeId;
        OrganizationContext = new OrganizationContext(document.BranchId, null, document.OfficeId);
    }
    
    public DocumentAuthorizationRequest(
        DocumentTypeId documentTypeId, PermissionId permissionId, OrganizationContext organizationContext = null)
    {
        DocumentTypeId = documentTypeId;
        PermissionId = permissionId;
        OrganizationContext = organizationContext;
    }
    
    public long UserId { get; set; }
    
    public OrganizationContext OrganizationContext { get; set; }
    
    public DocumentTypeId DocumentTypeId { get; }

    public PermissionId PermissionId { get; }
}