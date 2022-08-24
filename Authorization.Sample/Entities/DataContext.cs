namespace Authorization.Sample.Entities;

public class DataContext
{
    public DataContext()
    {
        BankUsers = new[]
        {
            new BankUser { Id = BankUserId.Superuser },
            new BankUser { Id = BankUserId.BankUser },
            new BankUser { Id = BankUserId.Supervisor },
            new BankUser { Id = BankUserId.BranchUser },
            new BankUser { Id = BankUserId.RegionalOfficeUser },
            new BankUser { Id = BankUserId.OfficeUser },
        }.AsQueryable();

        BankUserRoles = new[]
        {
            new BankUserRole { BankUserId = BankUserId.Superuser, RoleId = RoleId.Superuser },
            new BankUserRole { BankUserId = BankUserId.BankUser, RoleId = RoleId.BankUser },
            new BankUserRole { BankUserId = BankUserId.BankUser, RoleId = RoleId.Supervisor, EndDate = DateTimeOffset.UtcNow.AddYears(-1)},
            new BankUserRole { BankUserId = BankUserId.Supervisor, RoleId = RoleId.Supervisor },
            new BankUserRole { BankUserId = BankUserId.BranchUser, RoleId = RoleId.BankUser, BranchId = OrgStructure.BranchId },
            new BankUserRole { BankUserId = BankUserId.RegionalOfficeUser, RoleId = RoleId.BankUser, BranchId = OrgStructure.BranchId, RegionalOfficeId = OrgStructure.RegionalOfficeId },
            new BankUserRole { BankUserId = BankUserId.OfficeUser, RoleId = RoleId.BankUser, BranchId = OrgStructure.BranchId, RegionalOfficeId = OrgStructure.RegionalOfficeId, OfficeId = OrgStructure.OfficeId },
        }.AsQueryable();

        Roles = new[]
        {
            new Role { Id = RoleId.Superuser, Name = nameof(RoleId.Superuser) }, 
            new Role { Id = RoleId.BankUser, Name = nameof(RoleId.BankUser) },
            new Role { Id = RoleId.Supervisor, Name = nameof(RoleId.Supervisor) },
        }.AsQueryable();

        Permissions = new[]
        {
            new Permission { Id = PermissionId.View, Name = nameof(PermissionId.View) },
            new Permission { Id = PermissionId.Create, Name = nameof(PermissionId.Create) },
            new Permission { Id = PermissionId.Change, Name = nameof(PermissionId.Change) },
            new Permission { Id = PermissionId.Delete, Name = nameof(PermissionId.Delete) },
            new Permission { Id = PermissionId.Any, Name = nameof(PermissionId.Any) },
        }.AsQueryable();

        Securables = new[]
        {
            new Securable { Id = SecurableId.Document, Name = nameof(SecurableId.Document) },
            new Securable { Id = SecurableId.DocumentationFile, Name = nameof(SecurableId.DocumentationFile) },
            new Securable { Id = SecurableId.Any, Name = nameof(SecurableId.Any) },
        }.AsQueryable();

        RolePermissions = new[]
        {
            new RolePermission { RoleId = RoleId.BankUser, PermissionId = PermissionId.View, SecurableId = SecurableId.Document },
            new RolePermission { RoleId = RoleId.Supervisor, PermissionId = PermissionId.Any, SecurableId = SecurableId.Any },
        }.AsQueryable();

        Documents = new[]
        {
            new Document { Id = 1, BranchId = OrgStructure.BranchId, OfficeId = OrgStructure.OfficeId, DocumentTypeId = DocumentTypeId.Account },
            new Document { Id = 2, BranchId = OrgStructure.BranchId, OfficeId = OrgStructure.OfficeId, DocumentTypeId = DocumentTypeId.Account },
            new Document { Id = 3, BranchId = OrgStructure.BranchId, OfficeId = OrgStructure.OfficeId, DocumentTypeId = DocumentTypeId.Guarantee },
            new Document { Id = 4, BranchId = OrgStructure.BranchId, OfficeId = 4, DocumentTypeId = DocumentTypeId.Account },
            new Document { Id = 5, BranchId = OrgStructure.BranchId, OfficeId = 4, DocumentTypeId = DocumentTypeId.Guarantee },
        }.AsQueryable();

        DocumentTypes = new[]
        {
            new DocumentType { Id = DocumentTypeId.Account, Name = nameof(DocumentTypeId.Account) },
            new DocumentType { Id = DocumentTypeId.Guarantee, Name = nameof(DocumentTypeId.Guarantee) },
        }.AsQueryable();

        DocumentTypeRolePermissions = new[]
        {
            new DocumentTypeRolePermission { RoleId = RoleId.BankUser, DocumentTypeId = DocumentTypeId.Account, PermissionId = PermissionId.View },
            new DocumentTypeRolePermission { RoleId = RoleId.BankUser, DocumentTypeId = DocumentTypeId.Account, PermissionId = PermissionId.Change },
        }.AsQueryable();
    }
    
    public IQueryable<BankUser> BankUsers { get; }
    
    public IQueryable<BankUserRole> BankUserRoles { get; }

    public IQueryable<Role> Roles { get; }
    
    public IQueryable<Permission> Permissions { get; }
    
    public IQueryable<Securable> Securables { get; }
    
    public IQueryable<RolePermission> RolePermissions { get; }
    
    public IQueryable<Document> Documents { get; }
    
    public IQueryable<DocumentType> DocumentTypes { get; }
    
    public IQueryable<DocumentTypeRolePermission> DocumentTypeRolePermissions { get; }
}