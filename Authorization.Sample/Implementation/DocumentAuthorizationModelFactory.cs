using Authorization.Sample.Entities;
using Authorization.Sample.Services;

namespace Authorization.Sample.Implementation;

public class DocumentAuthorizationModelFactory : ResourceAuthorizationModelFactory, IAuthorizationModelFactory<DocumentAuthorizationModel>
{
    private readonly DataContext _context;
    private readonly IDemoService _demoService;
    private readonly ICurrentDateService _dateService;

    public DocumentAuthorizationModelFactory(DataContext context, IDemoService demoService, ICurrentDateService dateService) 
        : base(context, demoService, dateService)
    {
        _context = context;
        _demoService = demoService;
        _dateService = dateService;
    }
    
    public new DocumentAuthorizationModel PrepareModel()
    {
        var model = new DocumentAuthorizationModel(
            GetResourcePolicyRules(), 
            GetDocumentPolicyRules());
        
        return model;
    }

    protected IQueryable<DocumentPolicyRule> GetDocumentPolicyRules()
    {
        return from bankUserRole in _context.BankUserRoles
            join documentTypeRolePermission in _context.DocumentTypeRolePermissions on bankUserRole.RoleId equals documentTypeRolePermission.RoleId
            join permission in _context.Permissions on documentTypeRolePermission.PermissionId equals permission.Id
            where (bankUserRole.EndDate == null || bankUserRole.EndDate > _dateService.UtcNow) && (!_demoService.IsDemoModeActive || permission.IsReadonly) 
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