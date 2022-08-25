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

    public ITable<Account> Accounts => this.GetTable<Account>();

    public ITable<GL2Group> Gl2Groups => this.GetTable<GL2Group>();

    public ITable<GL2GroupRolePermission> Gl2GroupRolePermissions => this.GetTable<GL2GroupRolePermission>();

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
        this.CreateTable<Account>();
        this.CreateTable<GL2Group>();
        this.CreateTable<GL2GroupRolePermission>();

        Accounts.Insert(() => new Account { Id = 1, Number = "30101810400000000225", GL2 = "30101" });
        Accounts.Insert(() => new Account { Id = 2, Number = "30101810145250000974", GL2 = "30101" });
        Accounts.Insert(() => new Account { Id = 3, Number = "30101810200000000593", GL2 = "30101" });
        Accounts.Insert(() => new Account { Id = 4, Number = "30102810200000000790", GL2 = "30102" });

        Gl2Groups.Insert(() => new GL2Group { GL2GroupId = GL2GroupIds.Bank, GL2 = "30101" });
        Gl2Groups.Insert(() => new GL2Group { GL2GroupId = GL2GroupIds.Credit, GL2 = "30102" });

        Gl2GroupRolePermissions.Insert(() => new GL2GroupRolePermission { GL2GroupId = GL2GroupIds.Bank, RoleId = RoleId.BankUser, PermissionId = PermissionId.View });
        
        BankUsers.Insert(() => new BankUser { Id = BankUserId.Superuser });
        BankUsers.Insert(() => new BankUser { Id = BankUserId.BankUser });
        BankUsers.Insert(() => new BankUser { Id = BankUserId.Supervisor });
        BankUsers.Insert(() => new BankUser { Id = BankUserId.BranchUser });
        BankUsers.Insert(() => new BankUser { Id = BankUserId.RegionalOfficeUser });
        BankUsers.Insert(() => new BankUser { Id = BankUserId.OfficeUser });

        BankUserRoles.Insert(() => new BankUserRole { BankUserId = BankUserId.Superuser, RoleId = RoleId.Superuser });
        BankUserRoles.Insert(() => new BankUserRole { BankUserId = BankUserId.BankUser, RoleId = RoleId.BankUser });
        BankUserRoles.Insert(() => new BankUserRole { BankUserId = BankUserId.BankUser, RoleId = RoleId.Supervisor, EndDate = DateTimeOffset.UtcNow.AddYears(-1)});
        BankUserRoles.Insert(() => new BankUserRole { BankUserId = BankUserId.Supervisor, RoleId = RoleId.Supervisor });
        BankUserRoles.Insert(() => new BankUserRole { BankUserId = BankUserId.BranchUser, RoleId = RoleId.BankUser, BranchId = OrgIds.BranchId });
        BankUserRoles.Insert(() => new BankUserRole { BankUserId = BankUserId.RegionalOfficeUser, RoleId = RoleId.BankUser, BranchId = OrgIds.BranchId, RegionalOfficeId = OrgIds.RegionalOfficeId });
        BankUserRoles.Insert(() => new BankUserRole { BankUserId = BankUserId.OfficeUser, RoleId = RoleId.BankUser, BranchId = OrgIds.BranchId, RegionalOfficeId = OrgIds.RegionalOfficeId, OfficeId = OrgIds.OfficeId });

        Roles.Insert(() => new Role { Id = RoleId.Superuser, Name = nameof(RoleId.Superuser) });
        Roles.Insert(() => new Role { Id = RoleId.BankUser, Name = nameof(RoleId.BankUser) });
        Roles.Insert(() => new Role { Id = RoleId.Supervisor, Name = nameof(RoleId.Supervisor) });

        Permissions.Insert(() => new Permission { Id = PermissionId.View, Name = nameof(PermissionId.View), IsReadonly = true });
        Permissions.Insert(() => new Permission { Id = PermissionId.Create, Name = nameof(PermissionId.Create), IsReadonly = false });
        Permissions.Insert(() => new Permission { Id = PermissionId.Change, Name = nameof(PermissionId.Change), IsReadonly = false });
        Permissions.Insert(() => new Permission { Id = PermissionId.Delete, Name = nameof(PermissionId.Delete), IsReadonly = false });
        Permissions.Insert(() => new Permission { Id = PermissionId.Any, Name = nameof(PermissionId.Any), IsReadonly = false });

        Securables.Insert(() => new Securable { Id = SecurableId.Document, Name = nameof(SecurableId.Document) });
        Securables.Insert(() => new Securable { Id = SecurableId.Account, Name = nameof(SecurableId.Account) });
        Securables.Insert(() => new Securable { Id = SecurableId.DocumentationFile, Name = nameof(SecurableId.Account) });
        Securables.Insert(() => new Securable { Id = SecurableId.Any, Name = nameof(SecurableId.Any) });

        RolePermissions.Insert(() => new RolePermission { RoleId = RoleId.Supervisor, PermissionId = PermissionId.Any, SecurableId = SecurableId.Any });
        RolePermissions.Insert(() => new RolePermission { RoleId = RoleId.BankUser, PermissionId = PermissionId.View, SecurableId = SecurableId.DocumentationFile });
        
        Documents.Insert(() => new Document { Id = 1, BranchId = OrgIds.BranchId, OfficeId = OrgIds.OfficeId, DocumentTypeId = DocumentTypeId.Account });
        Documents.Insert(() => new Document { Id = 2, BranchId = OrgIds.BranchId, OfficeId = OrgIds.OfficeId, DocumentTypeId = DocumentTypeId.Account });
        Documents.Insert(() => new Document { Id = 3, BranchId = OrgIds.BranchId, OfficeId = OrgIds.OfficeId, DocumentTypeId = DocumentTypeId.Guarantee });
        Documents.Insert(() => new Document { Id = 4, BranchId = OrgIds.BranchId, OfficeId = 4, DocumentTypeId = DocumentTypeId.Account });
        Documents.Insert(() => new Document { Id = 5, BranchId = OrgIds.BranchId, OfficeId = 4, DocumentTypeId = DocumentTypeId.Guarantee });
       
        DocumentTypes.Insert(() => new DocumentType { Id = DocumentTypeId.Account, Name = nameof(DocumentTypeId.Account) });
        DocumentTypes.Insert(() => new DocumentType { Id = DocumentTypeId.Guarantee, Name = nameof(DocumentTypeId.Guarantee) });
        
        DocumentTypeRolePermissions.Insert(() => new DocumentTypeRolePermission { RoleId = RoleId.BankUser, DocumentTypeId = DocumentTypeId.Account, PermissionId = PermissionId.View });
        DocumentTypeRolePermissions.Insert(() => new DocumentTypeRolePermission { RoleId = RoleId.BankUser, DocumentTypeId = DocumentTypeId.Account, PermissionId = PermissionId.Change  });
    }
}