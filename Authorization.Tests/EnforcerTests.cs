using System.Linq;
using Authorization.Sample;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Authorization.Tests;

public class EnforcerTests
{
    [Fact]
    public void Enforce_BankUser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.BankUser);

        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.View)));
        Assert.False(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.Change)));
    }

    [Fact]
    public void Enforce_Superuser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.View)));
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.Change)));
    }

    [Fact]
    public void Enforce_Supervisor_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.View)));
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.Change)));
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.DocumentationFile, Permissions.Change)));
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.DocumentationFile, Permissions.Delete)));
    }
    
    private static Enforcer CreateEnforcer(BankUserId currentUser)
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddSingleton(new DataContext());
        serviceCollection.AddSingleton<ICurrentUserService>(new TestUserService(currentUser));
        serviceCollection.AddSingleton<IAuthorizationPolicyRuleQuery<AuthorizationPolicyRule>, TestAuthorizationPolicyRuleQuery>();
        serviceCollection.AddSingleton<IAuthorizationPolicyRuleQuery<RoleAuthorizationPolicyRule>, TestRoleAuthorizationPolicyRuleQuery>();
        serviceCollection.AddSingleton<IMatcher<AuthorizationRequest>, ResourcePermissionMatcher>();
        serviceCollection.AddSingleton<IMatcher<AuthorizationRequest>, SuperuserMatcher>();
        serviceCollection.AddSingleton<Enforcer>();

        return serviceCollection.BuildServiceProvider().GetService<Enforcer>();
    }
}

public class DocumentTypeEnforcerTests
{
    [Fact]
    public void Enforce_BankUser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.BankUser);
        
        Assert.True(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Account, Permissions.View)));
        Assert.False(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Account, Permissions.Change)));
        Assert.False(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.View)));
        Assert.False(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.Change)));
    }

    [Fact]
    public void Enforce_Superuser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        
        Assert.True(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Account, Permissions.View)));
        Assert.True(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Account, Permissions.Change)));
        Assert.True(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.View)));
        Assert.True(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.Change)));
    }
    
    private static Enforcer CreateEnforcer(BankUserId currentUser)
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddSingleton(new DataContext());
        serviceCollection.AddSingleton<ICurrentUserService>(new TestUserService(currentUser));
        serviceCollection.AddSingleton<IAuthorizationPolicyRuleQuery<AuthorizationPolicyRule>, TestAuthorizationPolicyRuleQuery>();
        serviceCollection.AddSingleton<IAuthorizationPolicyRuleQuery<RoleAuthorizationPolicyRule>, TestRoleAuthorizationPolicyRuleQuery>();
        serviceCollection.AddSingleton<IMatcher<AuthorizationRequest>, ResourcePermissionMatcher>();
        serviceCollection.AddSingleton<IMatcher<AuthorizationRequest>, SuperuserMatcher>();
        serviceCollection.AddSingleton<IAuthorizationPolicyRuleQuery<DocumentTypeAuthorizationPolicyRule>, TestDocumentTypeAuthorizationPolicyRuleQuery>();
        serviceCollection.AddSingleton<IMatcher<DocumentTypeAuthorizationRequest>, DocumentTypeMatcher>();
        serviceCollection.AddSingleton<IMatcher<DocumentTypeAuthorizationRequest>, DocumentTypeSuperuserMatcher>();
        serviceCollection.AddSingleton<Enforcer>();

        return serviceCollection.BuildServiceProvider().GetService<Enforcer>();
    }
}

public class DocumentTypeFilterTests
{
    [Fact]
    public void EnforceFilter_BankUser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.BankUser);
        var context = new DataContext();

        var documents = enforcer.EnforceFilter(context.Documents).ToArray();
        
        Assert.Equal(2, documents.Length);
        Assert.All(documents, d => Assert.Equal(d.DocumentTypeId, DocumentTypeId.Account));
    }
    
    [Fact]
    public void Enforce_Superuser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        var context = new DataContext();

        var documents = enforcer.EnforceFilter(context.Documents).ToArray();
        Assert.Equal(3, documents.Length);
    }
    
    private static Enforcer CreateEnforcer(BankUserId currentUser)
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddSingleton(new DataContext());
        serviceCollection.AddSingleton<ICurrentUserService>(new TestUserService(currentUser));
        serviceCollection.AddSingleton<IAuthorizationPolicyRuleQuery<AuthorizationPolicyRule>, TestAuthorizationPolicyRuleQuery>();
        serviceCollection.AddSingleton<IAuthorizationPolicyRuleQuery<RoleAuthorizationPolicyRule>, TestRoleAuthorizationPolicyRuleQuery>();
        serviceCollection.AddSingleton<IMatcher<AuthorizationRequest>, ResourcePermissionMatcher>();
        serviceCollection.AddSingleton<IMatcher<AuthorizationRequest>, SuperuserMatcher>();
        serviceCollection.AddSingleton<IAuthorizationPolicyRuleQuery<DocumentTypeAuthorizationPolicyRule>, TestDocumentTypeAuthorizationPolicyRuleQuery>();
        serviceCollection.AddSingleton<IMatcher<DocumentTypeAuthorizationRequest>, DocumentTypeMatcher>();
        serviceCollection.AddSingleton<IMatcher<DocumentTypeAuthorizationRequest>, DocumentTypeSuperuserMatcher>();
        serviceCollection.AddSingleton<IFilter<Document, AuthorizationFilterContext>, DocumentTypeFilter>();
        serviceCollection.AddSingleton<IFilter<Document, AuthorizationFilterContext>, SuperuserFilter>();
        serviceCollection.AddSingleton<Enforcer>();

        return serviceCollection.BuildServiceProvider().GetService<Enforcer>();
    }
}

public class SuperuserFilter : Filter<Document, RoleAuthorizationPolicyRule>
{
    public SuperuserFilter(IAuthorizationPolicyRuleQuery<RoleAuthorizationPolicyRule> rules) 
        : base(rules)
    {
    }

    protected override IQueryable<Document> Join(IQueryable<Document> query, AuthorizationFilterContext context, IQueryable<RoleAuthorizationPolicyRule> rules)
    {
        var resultQuery = from document in query
            where rules.Any(r => r.UserId == context.UserId && r.RoleName == "Superuser")
            select document;

        return resultQuery;
    }
}

public class DocumentTypeFilter : Filter<Document, DocumentTypeAuthorizationPolicyRule>
{
    public DocumentTypeFilter(IAuthorizationPolicyRuleQuery<DocumentTypeAuthorizationPolicyRule> rules) 
        : base(rules)
    {
    }

    protected override IQueryable<Document> Join(IQueryable<Document> query, AuthorizationFilterContext context, IQueryable<DocumentTypeAuthorizationPolicyRule> rules)
    {
        var resultQuery = from document in query
            join rule in rules on document.DocumentTypeId equals rule.DocumentTypeId
            where rule.UserId == context.UserId && rule.PermissionId == context.PermissionId
            select document;

        return resultQuery;
    }
}

public class TestAuthorizationPolicyRuleQuery : IAuthorizationPolicyRuleQuery<AuthorizationPolicyRule>
{
    private readonly DataContext _context;

    public TestAuthorizationPolicyRuleQuery(DataContext context)
    {
        _context = context;
    }
    
    public IQueryable<AuthorizationPolicyRule> PrepareQuery()
    {
        var query =
            from bankUserRole in _context.BankUserRoles
            join rolePermission in _context.RolePermissions on bankUserRole.RoleId equals rolePermission.RoleId
            select new AuthorizationPolicyRule
            {
                UserId = (long) bankUserRole.BankUserId, 
                Resource = rolePermission.SecurableId,
                Action = rolePermission.PermissionId
            };
        return query;
    }
}

public class TestRoleAuthorizationPolicyRuleQuery : IAuthorizationPolicyRuleQuery<RoleAuthorizationPolicyRule>
{
    private readonly DataContext _context;

    public TestRoleAuthorizationPolicyRuleQuery(DataContext context)
    {
        _context = context;
    }
    
    public IQueryable<RoleAuthorizationPolicyRule> PrepareQuery()
    {
        var query =
            from bankUserRole in _context.BankUserRoles
            join role in _context.Roles on bankUserRole.RoleId equals role.Id 
            select new RoleAuthorizationPolicyRule
            {
                UserId = (long) bankUserRole.BankUserId, 
                RoleName = role.Name
            };
        return query;
    }
}

public class DocumentTypeAuthorizationPolicyRule
{
    public long UserId { get; set; }

    public DocumentTypeId DocumentTypeId { get; set; }

    public PermissionId PermissionId { get; set; }

    public string RoleName { get; set; }
}

public class TestDocumentTypeAuthorizationPolicyRuleQuery : IAuthorizationPolicyRuleQuery<DocumentTypeAuthorizationPolicyRule>
{
    private readonly DataContext _context;

    public TestDocumentTypeAuthorizationPolicyRuleQuery(DataContext context)
    {
        _context = context;
    }
    
    public IQueryable<DocumentTypeAuthorizationPolicyRule> PrepareQuery()
    {
        var query =
            from bankUserRole in _context.BankUserRoles
            join documentTypeRolePermission in _context.DocumentTypeRolePermissions on bankUserRole.RoleId equals documentTypeRolePermission.RoleId
            join role in _context.Roles on bankUserRole.RoleId equals role.Id
            select new DocumentTypeAuthorizationPolicyRule
            { 
                UserId = (long) bankUserRole.BankUserId,
                DocumentTypeId = documentTypeRolePermission.DocumentTypeId,
                PermissionId = documentTypeRolePermission.PermissionId,
                RoleName = role.Name
            };

        return query;
    }
}

public class DocumentTypeMatcher : Matcher<DocumentTypeAuthorizationRequest, DocumentTypeAuthorizationPolicyRule>
{
    public DocumentTypeMatcher(IAuthorizationPolicyRuleQuery<DocumentTypeAuthorizationPolicyRule> authorizationPolicyRuleQuery) 
        : base(authorizationPolicyRuleQuery)
    {
    }

    protected override IQueryable<PolicyEffect> Match(DocumentTypeAuthorizationRequest request, IQueryable<DocumentTypeAuthorizationPolicyRule> rules)
    {
        return rules
            .Where(r => r.UserId == request.UserId && 
                       (r.PermissionId == request.PermissionId || r.PermissionId == PermissionId.Any) && 
                       (r.DocumentTypeId == request.DocumentTypeId))
            .Select(r => PolicyEffect.Allow);
    }
}

public class DocumentTypeSuperuserMatcher : SuperuserMatcherBase<DocumentTypeAuthorizationRequest>
{
    public DocumentTypeSuperuserMatcher(IAuthorizationPolicyRuleQuery<RoleAuthorizationPolicyRule> authorizationPolicyRuleQuery) 
        : base(authorizationPolicyRuleQuery)
    {
    }

    protected override IQueryable<PolicyEffect> Match(DocumentTypeAuthorizationRequest request, IQueryable<RoleAuthorizationPolicyRule> rules)
    {
        return Match(request.UserId, rules);
    }
}

public class DocumentTypeAuthorizationRequest : CurrentUserAuthorizationRequest
{
    public DocumentTypeAuthorizationRequest(DocumentTypeId documentTypeId, PermissionId permissionId)
    {
        DocumentTypeId = documentTypeId;
        PermissionId = permissionId;
    }

    public DocumentTypeId DocumentTypeId { get; set; }

    public PermissionId PermissionId { get; set; }
}

public class TestUserService : ICurrentUserService
{
    public TestUserService(BankUserId userId)
    {
        UserId = (long) userId;
    }

    public long UserId { get; }
}

public class DataContext
{
    public DataContext()
    {
        BankUsers = new[]
        {
            new BankUser { Id = BankUserId.Superuser },
            new BankUser { Id = BankUserId.BankUser },
            new BankUser { Id = BankUserId.Supervisor },
        }.AsQueryable();

        BankUserRoles = new[]
        {
            new BankUserRole { BankUserId = BankUserId.Superuser, RoleId = RoleId.Superuser },
            new BankUserRole { BankUserId = BankUserId.BankUser, RoleId = RoleId.BankUser },
            new BankUserRole { BankUserId = BankUserId.Supervisor, RoleId = RoleId.Supervisor }
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
            new Document { Id = 1, DocumentTypeId = DocumentTypeId.Account },
            new Document { Id = 2, DocumentTypeId = DocumentTypeId.Account },
            new Document { Id = 3, DocumentTypeId = DocumentTypeId.Guarantee },
        }.AsQueryable();

        DocumentTypes = new[]
        {
            new DocumentType { Id = DocumentTypeId.Account, Name = nameof(DocumentTypeId.Account) },
            new DocumentType { Id = DocumentTypeId.Guarantee, Name = nameof(DocumentTypeId.Guarantee) },
        }.AsQueryable();

        DocumentTypeRolePermissions = new[]
        {
            new DocumentTypeRolePermission { RoleId = RoleId.BankUser, DocumentTypeId = DocumentTypeId.Account, PermissionId = PermissionId.View },
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

public enum BankUserId
{
    Superuser = 1, BankUser = 2, Supervisor = 3
}

public enum RoleId
{
    Superuser = 1, BankUser = 2, Supervisor = 3
}

public class BankUser
{
    public BankUserId Id { get; set; }
}

public class Role
{
    public RoleId Id { get; set; }

    public string Name { get; set; }
}

public class RolePermission
{
    public RoleId RoleId { get; set; }
    
    public SecurableId SecurableId { get; set; }
    
    public PermissionId PermissionId { get; set; }
}

public class BankUserRole
{
    public BankUserId BankUserId { get; set; }
    
    public RoleId RoleId { get; set; }
}

public class Permission
{
    public PermissionId Id { get; set; }

    public string Name { get; set; }
}

public class Securable
{
    public SecurableId Id { get; set; }

    public string Name { get; set; }
}

public class Document
{
    public long Id { get; set; }

    public DocumentTypeId DocumentTypeId { get; set; }
}

public class DocumentType
{
    public DocumentTypeId Id { get; set; }

    public string Name { get; set; }
}

public enum DocumentTypeId
{
    Account = 1, Guarantee = 2
}

public class DocumentTypeRolePermission
{
    public RoleId RoleId { get; set; }

    public PermissionId PermissionId { get; set; }

    public DocumentTypeId DocumentTypeId { get; set; }
}
