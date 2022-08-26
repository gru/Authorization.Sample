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
    
    public IQueryable<PolicyRule> UserPolicyRules(long userId, PermissionId permissionId, OrganizationContext organizationContext)
    {
        if (_options.AllowReadPermissionsOnly && !_readOnlyPermissions.Value.Contains(permissionId))
            return Enumerable.Empty<PolicyRule>().AsQueryable();
        
        var id = (BankUserId) userId;

        var orgContextBankUserRoles = ApplyOrganizationContextFilter(_context.BankUserRoles, organizationContext);
        
        orgContextBankUserRoles = ApplyEndDateFilter(orgContextBankUserRoles, _dateService.UtcNow);
        
        var resourceRules =
            from bankUserRole in orgContextBankUserRoles
            join rolePermission in _context.RolePermissions on bankUserRole.RoleId equals rolePermission.RoleId
            where bankUserRole.BankUserId == id && 
                  (rolePermission.PermissionId == permissionId || 
                   rolePermission.PermissionId == PermissionId.Any)
            select new PolicyRule
            {
                UserId = (long)bankUserRole.BankUserId,
                PermissionId = rolePermission.PermissionId,
                RoleId = rolePermission.RoleId
            };
        
        var documentRoles = 
            from bankUserRole in orgContextBankUserRoles
            join documentTypeRolePermission in _context.DocumentTypeRolePermissions on bankUserRole.RoleId equals documentTypeRolePermission.RoleId
            where bankUserRole.BankUserId == id && 
                  (documentTypeRolePermission.PermissionId == permissionId || 
                   documentTypeRolePermission.PermissionId == PermissionId.Any)
            select new PolicyRule
            {
                UserId = (long)bankUserRole.BankUserId,
                PermissionId = documentTypeRolePermission.PermissionId,
                RoleId = documentTypeRolePermission.RoleId
            };

        var accountGroups = 
            from bankUserRole in orgContextBankUserRoles
            join gl2GroupRolePermission in _context.Gl2GroupRolePermissions on bankUserRole.RoleId equals gl2GroupRolePermission.RoleId
            where bankUserRole.BankUserId == id && 
                  (gl2GroupRolePermission.PermissionId == permissionId || 
                   gl2GroupRolePermission.PermissionId == PermissionId.Any)
            select new PolicyRule
            {
                UserId = (long)bankUserRole.BankUserId,
                PermissionId = gl2GroupRolePermission.PermissionId,
                RoleId = gl2GroupRolePermission.RoleId
            };

        return resourceRules.Union(documentRoles).Union(accountGroups);
    }
    
    public bool InRole(long userId, RoleId roleId)
    {
        var id = (BankUserId)userId;
        
        return _context.BankUserRoles.Any(bur => bur.BankUserId == id && bur.RoleId == roleId);
    }
    
    public bool InResourceRole(long userId, RoleId roleId, SecurableId securableId, PermissionId permissionId)
    {
        var id = (BankUserId) userId;
        
        var query =
            from bankUserRole in _context.BankUserRoles
            join rolePermission in _context.RolePermissions on bankUserRole.RoleId equals rolePermission.RoleId
            where bankUserRole.BankUserId == id && 
                  bankUserRole.RoleId == roleId && 
                  (rolePermission.SecurableId == securableId || 
                   rolePermission.SecurableId == SecurableId.Any) &&
                  (rolePermission.PermissionId == permissionId ||
                   rolePermission.PermissionId == PermissionId.Any)
            select 1;
        
        return query.Any();
    }

    public bool HasResourcePermission(long userId, SecurableId securableId, PermissionId permissionId)
    {
        var id = (BankUserId) userId;

        var query = from bankUserRole in _context.BankUserRoles
            join rolePermission in _context.RolePermissions on bankUserRole.RoleId equals rolePermission.RoleId
            where bankUserRole.BankUserId == id && 
                  (rolePermission.SecurableId == securableId || 
                   rolePermission.SecurableId == SecurableId.Any) &&
                  (rolePermission.PermissionId == permissionId ||
                   rolePermission.PermissionId == PermissionId.Any)
            select 1;
        
        return query.Any();
    }
    
    public bool InDocumentTypeRole(long userId, RoleId roleId, DocumentTypeId documentTypeId, PermissionId permissionId)
    {
        var id = (BankUserId) userId;
        
        var documentRoles = 
            from bankUserRole in _context.BankUserRoles
            join documentTypeRolePermission in _context.DocumentTypeRolePermissions on bankUserRole.RoleId equals documentTypeRolePermission.RoleId
            where bankUserRole.BankUserId == id && 
                  documentTypeRolePermission.RoleId == roleId && 
                  documentTypeRolePermission.DocumentTypeId == documentTypeId &&
                  (documentTypeRolePermission.PermissionId == permissionId ||
                   documentTypeRolePermission.PermissionId == PermissionId.Any)
            select 1;
        
        return documentRoles.Any();
    }
    
    public IEnumerable<DocumentTypeId> UserAllowedDocumentTypes(long userId, PermissionId permissionId, OrganizationContext organizationContext)
    {
        var id = (BankUserId) userId;
        
        var orgContextBankUserRoles = ApplyOrganizationContextFilter(_context.BankUserRoles, organizationContext);

        var query =
            from bankUserRole in orgContextBankUserRoles
            join documentTypeRolePermission in _context.DocumentTypeRolePermissions on bankUserRole.RoleId equals documentTypeRolePermission.RoleId
            where bankUserRole.BankUserId == id && documentTypeRolePermission.PermissionId == permissionId
            select documentTypeRolePermission.DocumentTypeId;

        return query;
    }
    
    public bool InGL2GroupRole(long userId, RoleId roleId, string gl2, PermissionId permissionId)
    {
        var id = (BankUserId) userId;
        var groups = _gl2Lookup.Value[gl2];
            
        var query = 
            from bankUserRole in _context.BankUserRoles
            join gl2GroupRolePermission in _context.Gl2GroupRolePermissions on bankUserRole.RoleId equals gl2GroupRolePermission.RoleId
            where bankUserRole.BankUserId == id && 
                  gl2GroupRolePermission.RoleId == roleId && 
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

    private IQueryable<BankUserRole> ApplyOrganizationContextFilter(IQueryable<BankUserRole> query, OrganizationContext ctx)
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

        return query;
    }

    private IQueryable<BankUserRole> ApplyEndDateFilter(IQueryable<BankUserRole> query, DateTimeOffset nowUtc)
    {
        return query.Where(bur => bur.EndDate == null || bur.EndDate > nowUtc);
    }
}