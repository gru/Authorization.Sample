using Authorization.Sample.Entities;
using Authorization.Sample.Services;

namespace Authorization.Sample.Implementation;

public class AuthorizationModel
{
    private readonly DataContext _context;
    private readonly AuthorizationModelOptions _options;
    private readonly ICurrentDateService _dateService;
    private readonly Lazy<ILookup<string, long>> _gl2Lookup;
    private readonly Lazy<HashSet<PermissionId>> _readOnlyPermissions;

    public AuthorizationModel(DataContext context, AuthorizationModelOptions options, ICurrentDateService dateService)
    {
        _context = context;
        _options = options;
        _dateService = dateService;
        _gl2Lookup = new Lazy<ILookup<string, long>>(() => 
            _context.Gl2Groups
                .Select(g => new { g.GL2GroupId, g.GL2 })
                .ToLookup(g => g.GL2, g => g.GL2GroupId));
        _readOnlyPermissions = new Lazy<HashSet<PermissionId>>(() =>
            _context.Permissions
                .Where(p => p.IsReadonly)
                .Select(p => p.Id)
                .ToHashSet());
    }

    public bool InResourceRole(long userId, SecurableId securableId, PermissionId permissionId, OrganizationContext organizationContext)
    {
        if (IsRequestedPermissionNotAllowed(permissionId))
            return false;
        
        var userRoles = ApplyUserBankRoleFilters(_context.BankUserRoles, organizationContext);
        
        var id = (BankUserId) userId;
        
        var query = from bankUserRole in userRoles
            join rolePermission in _context.RolePermissions on bankUserRole.RoleId equals rolePermission.RoleId
            where bankUserRole.BankUserId == id && 
                  (rolePermission.SecurableId == securableId || 
                   rolePermission.SecurableId == SecurableId.Any) &&
                  (rolePermission.PermissionId == permissionId ||
                   rolePermission.PermissionId == PermissionId.Any)
            select 1;
        
        return query.Any();
    }
    
    public bool InDocumentTypeRole(long userId, DocumentTypeId documentTypeId, PermissionId permissionId, OrganizationContext organizationContext)
    {
        if (IsRequestedPermissionNotAllowed(permissionId))
            return false;
        
        var userRoles = ApplyUserBankRoleFilters(_context.BankUserRoles, organizationContext);
        
        var id = (BankUserId) userId;
        
        var documentRoles = 
            from bankUserRole in userRoles
            join documentTypeRolePermission in _context.DocumentTypeRolePermissions on bankUserRole.RoleId equals documentTypeRolePermission.RoleId
            where bankUserRole.BankUserId == id && 
                  documentTypeRolePermission.DocumentTypeId == documentTypeId &&
                  (documentTypeRolePermission.PermissionId == permissionId ||
                   documentTypeRolePermission.PermissionId == PermissionId.Any)
            select 1;
        
        return documentRoles.Any();
    }
    
    public IEnumerable<DocumentTypeId> UserAllowedDocumentTypes(long userId, PermissionId permissionId, OrganizationContext organizationContext)
    {
        var bankRoleFilters = ApplyUserBankRoleFilters(_context.BankUserRoles, organizationContext);

        var id = (BankUserId) userId;
        
        var query =
            from bankUserRole in bankRoleFilters
            join documentTypeRolePermission in _context.DocumentTypeRolePermissions on bankUserRole.RoleId equals documentTypeRolePermission.RoleId
            where bankUserRole.BankUserId == id && documentTypeRolePermission.PermissionId == permissionId
            select documentTypeRolePermission.DocumentTypeId;

        return query;
    }
    
    public bool InGL2GroupRole(long userId, string gl2, PermissionId permissionId, OrganizationContext organizationContext)
    {
        if (IsRequestedPermissionNotAllowed(permissionId))
            return false;
        
        var userRoles = ApplyUserBankRoleFilters(_context.BankUserRoles, organizationContext);
        
        var id = (BankUserId) userId;
        var groups = _gl2Lookup.Value[gl2];

        var query = 
            from bankUserRole in userRoles
            join gl2GroupRolePermission in _context.Gl2GroupRolePermissions on bankUserRole.RoleId equals gl2GroupRolePermission.RoleId
            where bankUserRole.BankUserId == id && 
                  groups.Contains(gl2GroupRolePermission.GL2GroupId) &&
                  (gl2GroupRolePermission.PermissionId == permissionId ||
                   gl2GroupRolePermission.PermissionId == PermissionId.Any)
            select new PolicyRule
            {
                UserId = (long)bankUserRole.BankUserId,
                PermissionId = gl2GroupRolePermission.PermissionId,
                RoleId = gl2GroupRolePermission.RoleId
            };
        
        return query.Any();
    }

    private IQueryable<BankUserRole> ApplyUserBankRoleFilters(IQueryable<BankUserRole> query, OrganizationContext ctx)
    {
        if (ctx == null)
        {
            query = query
                .Where(bur => bur.BranchId == null && bur.RegionalOfficeId == null && bur.OfficeId == null);
        }
        else
        {
            query = query
                .Where(bur => (bur.BranchId == null && bur.RegionalOfficeId == null && bur.OfficeId == null) ||
                            (bur.BranchId == ctx.BranchId && 
                             (bur.RegionalOfficeId == null || 
                              (ctx.RegionalOfficeId == null && ctx.OfficeId != null) || 
                              (bur.RegionalOfficeId == ctx.RegionalOfficeId)) && 
                             (bur.OfficeId == null || bur.OfficeId == ctx.OfficeId)));
        }

        var utcNow = _dateService.UtcNow;
        
        return query.Where(bur => bur.EndDate == null || bur.EndDate > utcNow);
    }

    private bool IsRequestedPermissionNotAllowed(PermissionId permissionId)
    {
        return _options.AllowReadPermissionsOnly && !_readOnlyPermissions.Value.Contains(permissionId);
    }
}