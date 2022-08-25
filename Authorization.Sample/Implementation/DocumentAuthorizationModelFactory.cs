using Authorization.Sample.Entities;
using Authorization.Sample.Services;

namespace Authorization.Sample.Implementation;

public class DocumentAuthorizationModelFactory : ResourceAuthorizationModelFactory, IAuthorizationModelFactory<DocumentAuthorizationModel>
{
    private readonly DataContext _context;
    private readonly ICurrentDateService _dateService;

    public DocumentAuthorizationModelFactory(DataContext context, ICurrentDateService dateService) 
        : base(context, dateService)
    {
        _context = context;
        _dateService = dateService;
    }
    
    public new DocumentAuthorizationModel PrepareModel()
    {
        var model = new DocumentAuthorizationModel(
            GetResourcePolicyRules(), 
            GetRolePolicyRules(), 
            GetDocumentPolicyRules(),
            GetPermissions());
        
        return model;
    }

    protected IQueryable<DocumentPolicyRule> GetDocumentPolicyRules()
    {
        return from bankUserRole in _context.BankUserRoles
            join documentTypeRolePermission in _context.DocumentTypeRolePermissions on bankUserRole.RoleId equals documentTypeRolePermission.RoleId
            join permission in _context.Permissions on documentTypeRolePermission.PermissionId equals permission.Id
            where bankUserRole.EndDate == null || bankUserRole.EndDate > _dateService.UtcNow
            select new DocumentPolicyRule
            { 
                UserId = (long) bankUserRole.BankUserId,
                DocumentTypeId = documentTypeRolePermission.DocumentTypeId,
                PermissionId = documentTypeRolePermission.PermissionId,
                BranchId = bankUserRole.BranchId,
                RegionalOfficeId = bankUserRole.RegionalOfficeId,
                OfficeId = bankUserRole.OfficeId
            };
    }
}