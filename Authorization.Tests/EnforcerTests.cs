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
    }
    
    public IQueryable<BankUser> BankUsers { get; }
    
    public IQueryable<BankUserRole> BankUserRoles { get; }

    public IQueryable<Role> Roles { get; }
    
    public IQueryable<Permission> Permissions { get; }
    
    public IQueryable<Securable> Securables { get; }
    
    public IQueryable<RolePermission> RolePermissions { get; }
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