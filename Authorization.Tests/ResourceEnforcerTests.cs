using System.Collections.Generic;
using System.Linq;
using Authorization.Sample;
using Authorization.Tests.Entities;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Authorization.Tests;

public class ResourceEnforcerTests
{
    [Fact]
    public void Enforce_BankUser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.BankUser);

        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.View)));
        Assert.False(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.Change)));
    }

    [Fact]
    public void Enforce_BranchUser_Permissions_With_OrgContext()
    {
        var enforcer = CreateEnforcer(BankUserId.BranchUser);

        Assert.False(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.View)));
        Assert.False(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.Change)));
        
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.View,
            new OrganizationContext(OrgStructure.BranchId))));
        Assert.False(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.Change,
            new OrganizationContext(OrgStructure.BranchId))));
        
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.View,
            new OrganizationContext(OrgStructure.BranchId, OrgStructure.RegionalOfficeId))));
        Assert.False(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.Change,
            new OrganizationContext(OrgStructure.BranchId, OrgStructure.RegionalOfficeId))));
        
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.View,
            new OrganizationContext(OrgStructure.BranchId, OrgStructure.RegionalOfficeId, OrgStructure.OfficeId))));
        Assert.False(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.Change,
            new OrganizationContext(OrgStructure.BranchId, OrgStructure.RegionalOfficeId, OrgStructure.OfficeId))));
    }
    
    [Fact]
    public void Enforce_Superuser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.View)));
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.Change)));
    }

    [Theory]
    [MemberData(nameof(GetOrgStructure))]
    public void Enforce_Superuser_Permissions_With_OrgContext(OrganizationContext organizationContext)
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.View, organizationContext)));
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.Change, organizationContext)));
    }

    [Fact]
    public void Enforce_Supervisor_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Supervisor);
        
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.View)));
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.Change)));
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.DocumentationFile, Permissions.Change)));
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.DocumentationFile, Permissions.Delete)));
    }
    
    [Theory]
    [MemberData(nameof(GetOrgStructure))]
    public void Enforce_Supervisor_Permissions_With_OrgContext(OrganizationContext organizationContext)
    {
        var enforcer = CreateEnforcer(BankUserId.Supervisor);
        
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.View, organizationContext)));
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.Document, Permissions.Change, organizationContext)));
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.DocumentationFile, Permissions.Change, organizationContext)));
        Assert.True(enforcer.Enforce(new AuthorizationRequest(Securables.DocumentationFile, Permissions.Delete, organizationContext)));
    }
    
    public static IEnumerable<object[]> GetOrgStructure()
    {
        yield return new object[] { new OrganizationContext(OrgStructure.BranchId) };
        yield return new object[] { new OrganizationContext(OrgStructure.BranchId, OrgStructure.RegionalOfficeId) };
        yield return new object[] { new OrganizationContext(OrgStructure.BranchId, OrgStructure.RegionalOfficeId, OrgStructure.OfficeId) };
    }
    
    private static Enforcer CreateEnforcer(BankUserId currentUser)
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddSingleton(new DataContext());
        serviceCollection.AddSingleton<ICurrentUserService>(new TestUserService(currentUser));
        serviceCollection.AddSingleton<IPolicyRuleQuery<ResourcePolicyRule>, ResourcePolicyRuleQuery>();
        serviceCollection.AddSingleton<IPolicyRuleQuery<RolePolicyRule>, RolePolicyRuleQuery>();
        serviceCollection.AddSingleton<IMatcher<AuthorizationRequest>, ResourcePermissionMatcher>();
        serviceCollection.AddSingleton<IMatcher<AuthorizationRequest>, SuperuserMatcher>();
        serviceCollection.AddSingleton<Enforcer>();

        return serviceCollection.BuildServiceProvider().GetService<Enforcer>();
    }
}

public class ResourcePolicyRuleQuery : IPolicyRuleQuery<ResourcePolicyRule>
{
    private readonly DataContext _context;

    public ResourcePolicyRuleQuery(DataContext context)
    {
        _context = context;
    }
    
    public IQueryable<ResourcePolicyRule> PrepareQuery()
    {
        var query =
            from bankUserRole in _context.BankUserRoles
            join rolePermission in _context.RolePermissions on bankUserRole.RoleId equals rolePermission.RoleId
            select new ResourcePolicyRule
            {
                UserId = (long) bankUserRole.BankUserId, 
                Resource = rolePermission.SecurableId,
                Action = rolePermission.PermissionId, 
                BranchId = bankUserRole.BranchId,
                RegionalOfficeId = bankUserRole.RegionalOfficeId,
                OfficeId = bankUserRole.OfficeId
            };
        return query;
    }
}

public class RolePolicyRuleQuery : IPolicyRuleQuery<RolePolicyRule>
{
    private readonly DataContext _context;

    public RolePolicyRuleQuery(DataContext context)
    {
        _context = context;
    }
    
    public IQueryable<RolePolicyRule> PrepareQuery()
    {
        var query =
            from bankUserRole in _context.BankUserRoles
            join role in _context.Roles on bankUserRole.RoleId equals role.Id 
            select new RolePolicyRule
            {
                UserId = (long) bankUserRole.BankUserId, 
                RoleName = role.Name, 
                BranchId = bankUserRole.BranchId,
                RegionalOfficeId = bankUserRole.RegionalOfficeId,
                OfficeId = bankUserRole.OfficeId
            };
        return query;
    }
}