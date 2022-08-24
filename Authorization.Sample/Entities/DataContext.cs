using LinqToDB;
using LinqToDB.Configuration;
using LinqToDB.Data;

namespace Authorization.Sample.Entities;

public class DataContext : DataConnection
{
    public DataContext(LinqToDBConnectionOptions options)
        : base(options)
    {
    }

    public ITable<BankUser> BankUsers => this.GetTable<BankUser>();
    
    public ITable<BankUserRole> BankUserRoles => this.GetTable<BankUserRole>();

    public ITable<Role> Roles => this.GetTable<Role>();
    
    public ITable<Permission> Permissions => this.GetTable<Permission>();
    
    public ITable<Securable> Securables => this.GetTable<Securable>();
    
    public ITable<RolePermission> RolePermissions => this.GetTable<RolePermission>();
    
    public ITable<Document> Documents => this.GetTable<Document>();
    
    public ITable<DocumentType> DocumentTypes => this.GetTable<DocumentType>();
    
    public ITable<DocumentTypeRolePermission> DocumentTypeRolePermissions => this.GetTable<DocumentTypeRolePermission>();

    public void CreateTestData()
    {
        this.CreateTable<BankUser>();
        this.CreateTable<Role>();
        this.CreateTable<Permission>();
        this.CreateTable<Securable>();
        this.CreateTable<DocumentType>();
        this.CreateTable<Document>();
        this.CreateTable<BankUserRole>();
        this.CreateTable<RolePermission>();
        this.CreateTable<DocumentTypeRolePermission>();
        
        BankUsers.Insert(() => new BankUser { Id = BankUserId.BankUser });
        BankUsers.Insert(() => new BankUser { Id = BankUserId.Supervisor });
        BankUsers.Insert(() => new BankUser { Id = BankUserId.BranchUser });
        BankUsers.Insert(() => new BankUser { Id = BankUserId.RegionalOfficeUser });
        BankUsers.Insert(() => new BankUser { Id = BankUserId.OfficeUser });

        BankUserRoles.Insert(() => new BankUserRole { BankUserId = BankUserId.BankUser, RoleId = RoleId.BankUser });
        BankUserRoles.Insert(() => new BankUserRole { BankUserId = BankUserId.BankUser, RoleId = RoleId.Supervisor, EndDate = DateTimeOffset.UtcNow.AddYears(-1)});
        BankUserRoles.Insert(() => new BankUserRole { BankUserId = BankUserId.Supervisor, RoleId = RoleId.Supervisor });
        BankUserRoles.Insert(() => new BankUserRole { BankUserId = BankUserId.BranchUser, RoleId = RoleId.BankUser, BranchId = OrgStructure.BranchId });
        BankUserRoles.Insert(() => new BankUserRole { BankUserId = BankUserId.RegionalOfficeUser, RoleId = RoleId.BankUser, BranchId = OrgStructure.BranchId, RegionalOfficeId = OrgStructure.RegionalOfficeId });
        BankUserRoles.Insert(() => new BankUserRole { BankUserId = BankUserId.OfficeUser, RoleId = RoleId.BankUser, BranchId = OrgStructure.BranchId, RegionalOfficeId = OrgStructure.RegionalOfficeId, OfficeId = OrgStructure.OfficeId });

        Roles.Insert(() => new Role { Id = RoleId.BankUser, Name = nameof(RoleId.BankUser) });
        Roles.Insert(() => new Role { Id = RoleId.Supervisor, Name = nameof(RoleId.Supervisor) });

        Permissions.Insert(() => new Permission { Id = PermissionId.View, Name = nameof(PermissionId.View), IsReadonly = true });
        Permissions.Insert(() => new Permission { Id = PermissionId.Create, Name = nameof(PermissionId.Create), IsReadonly = false });
        Permissions.Insert(() => new Permission { Id = PermissionId.Change, Name = nameof(PermissionId.Change), IsReadonly = false });
        Permissions.Insert(() => new Permission { Id = PermissionId.Delete, Name = nameof(PermissionId.Delete), IsReadonly = false });
        Permissions.Insert(() => new Permission { Id = PermissionId.Any, Name = nameof(PermissionId.Any), IsReadonly = false });

        Securables.Insert(() => new Securable { Id = SecurableId.Document, Name = nameof(SecurableId.Document) });
        Securables.Insert(() => new Securable { Id = SecurableId.DocumentationFile, Name = nameof(SecurableId.DocumentationFile) });
        Securables.Insert(() => new Securable { Id = SecurableId.Any, Name = nameof(SecurableId.Any) });

        RolePermissions.Insert(() => new RolePermission { RoleId = RoleId.BankUser, PermissionId = PermissionId.View, SecurableId = SecurableId.Document });
        RolePermissions.Insert(() => new RolePermission { RoleId = RoleId.Supervisor, PermissionId = PermissionId.Any, SecurableId = SecurableId.Any });
        
        Documents.Insert(() => new Document { Id = 1, BranchId = OrgStructure.BranchId, OfficeId = OrgStructure.OfficeId, DocumentTypeId = DocumentTypeId.Account });
        Documents.Insert(() => new Document { Id = 2, BranchId = OrgStructure.BranchId, OfficeId = OrgStructure.OfficeId, DocumentTypeId = DocumentTypeId.Account });
        Documents.Insert(() => new Document { Id = 3, BranchId = OrgStructure.BranchId, OfficeId = OrgStructure.OfficeId, DocumentTypeId = DocumentTypeId.Guarantee });
        Documents.Insert(() => new Document { Id = 4, BranchId = OrgStructure.BranchId, OfficeId = 4, DocumentTypeId = DocumentTypeId.Account });
        Documents.Insert(() => new Document { Id = 5, BranchId = OrgStructure.BranchId, OfficeId = 4, DocumentTypeId = DocumentTypeId.Guarantee });
       
        DocumentTypes.Insert(() => new DocumentType { Id = DocumentTypeId.Account, Name = nameof(DocumentTypeId.Account) });
        DocumentTypes.Insert(() => new DocumentType { Id = DocumentTypeId.Guarantee, Name = nameof(DocumentTypeId.Guarantee) });
        
        DocumentTypeRolePermissions.Insert(() => new DocumentTypeRolePermission { RoleId = RoleId.BankUser, DocumentTypeId = DocumentTypeId.Account, PermissionId = PermissionId.View, IsReadonly = true });
        DocumentTypeRolePermissions.Insert(() => new DocumentTypeRolePermission { RoleId = RoleId.BankUser, DocumentTypeId = DocumentTypeId.Account, PermissionId = PermissionId.Change, IsReadonly = false  });
    }
}