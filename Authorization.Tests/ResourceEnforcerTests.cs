using System;
using System.Collections;
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

        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.View)));
        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.Change)));
    }

    [Fact]
    public void Enforce_BranchUser_Permissions_With_OrgContext()
    {
        var enforcer = CreateEnforcer(BankUserId.BranchUser);

        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.View)));
        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.Change)));

        var data = new OrgStructureClassData();
        foreach (var organizationContext in data.EnumerateContexts())
        {
            Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.View, organizationContext)));
            Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.Change, organizationContext)));
        }
    }
    
    [Fact]
    public void Enforce_RegionalOfficeUser_Permissions_With_OrgContext()
    {
        var enforcer = CreateEnforcer(BankUserId.RegionalOfficeUser);

        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.View)));
        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.Change)));

        var data = new OrgStructureClassData();
        foreach (var organizationContext in data.EnumerateContexts().Take(OrgContextCount.BranchTakeCount))
        {
            Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.View, organizationContext)));
            Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.Change, organizationContext)));
        }
        
        foreach (var organizationContext in data.EnumerateContexts().Skip(OrgContextCount.RegionalOfficeSkipCount))
        {
            Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.View, organizationContext)));
            Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.Change, organizationContext)));
        }
    }
    
    [Fact]
    public void Enforce_OfficeUser_Permissions_With_OrgContext()
    {
        var enforcer = CreateEnforcer(BankUserId.OfficeUser);

        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.View)));
        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.Change)));

        var data = new OrgStructureClassData();
        foreach (var organizationContext in data.EnumerateContexts().Take(OrgContextCount.RegionalOfficeTakeCount))
        {
            Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.View, organizationContext)));
            Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.Change, organizationContext)));
        }
        
        foreach (var organizationContext in data.EnumerateContexts().Skip(OrgContextCount.OfficeSkipCount))
        {
            Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.View, organizationContext)));
            Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.Change, organizationContext)));
        }
    }
    
    [Fact]
    public void Enforce_Superuser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.View)));
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.Change)));
    }

    [Theory]
    [ClassData(typeof(OrgStructureClassData))]
    public void Enforce_Superuser_Permissions_With_OrgContext(OrganizationContext organizationContext)
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.View, organizationContext)));
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.Change, organizationContext)));
    }

    [Fact]
    public void Enforce_Supervisor_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Supervisor);
        
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.View)));
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.Change)));
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.DocumentationFile, Permissions.Change)));
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.DocumentationFile, Permissions.Delete)));
    }
    
    [Theory]
    [ClassData(typeof(OrgStructureClassData))]
    public void Enforce_Supervisor_Permissions_With_OrgContext(OrganizationContext organizationContext)
    {
        var enforcer = CreateEnforcer(BankUserId.Supervisor);
        
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.View, organizationContext)));
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, Permissions.Change, organizationContext)));
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.DocumentationFile, Permissions.Change, organizationContext)));
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.DocumentationFile, Permissions.Delete, organizationContext)));
    }
    
    private static Enforcer CreateEnforcer(BankUserId currentUser)
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddSingleton(new DataContext());
        serviceCollection.AddSingleton<ICurrentUserService>(new TestUserService(currentUser));
        serviceCollection.AddSingleton<ICurrentDateService>(new TestCurrentDateService(DateTimeOffset.Now));
        serviceCollection.AddSingleton<IAuthorizationModelFactory<ResourceAuthorizationModel>, ResourceAuthorizationModelFactory>();
        serviceCollection.AddSingleton<IMatcher<ResourceAuthorizationRequest>, ResourcePermissionMatcher>();
        serviceCollection.AddSingleton<Enforcer>();

        return serviceCollection.BuildServiceProvider().GetService<Enforcer>();
    }
}

public class OrgStructureClassData : IEnumerable<object[]>
{
    public IEnumerable<OrganizationContext> EnumerateContexts()
    {
        return this.SelectMany(arr => arr).Cast<OrganizationContext>();
    }

    public IEnumerator<object[]> GetEnumerator()
    { 
        yield return new object[] { new OrganizationContext(OrgStructure.BranchId) };
        yield return new object[] { new OrganizationContext(OrgStructure.BranchId, OrgStructure.RegionalOfficeId) };
        yield return new object[] { new OrganizationContext(OrgStructure.BranchId, OrgStructure.RegionalOfficeId, OrgStructure.OfficeId) };
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }
}

public static class OrgContextCount
{
    public const int BranchSkipCount = 0;
    public const int RegionalOfficeSkipCount = 1;
    public const int OfficeSkipCount = 2;
    
    public const int BranchTakeCount = 1;
    public const int RegionalOfficeTakeCount = 2;
    public const int OfficeTakeCount = 3;
}

public class ResourceAuthorizationModelFactory : IAuthorizationModelFactory<ResourceAuthorizationModel>
{
    private readonly DataContext _context;
    private readonly ICurrentDateService _dateService;

    public ResourceAuthorizationModelFactory(DataContext context, ICurrentDateService dateService)
    {
        _context = context;
        _dateService = dateService;
    }

    public ResourceAuthorizationModel PrepareModel()
    {
        var model = new ResourceAuthorizationModel(GetResourcePolicyRules(), GetRolePolicyRules());
        return model;
    }

    protected IQueryable<ResourcePolicyRule> GetResourcePolicyRules()
    {
        return from bankUserRole in _context.BankUserRoles
            join rolePermission in _context.RolePermissions on bankUserRole.RoleId equals rolePermission.RoleId
            where bankUserRole.EndDate == null || bankUserRole.EndDate > _dateService.UtcNow
            select new ResourcePolicyRule
            {
                UserId = (long) bankUserRole.BankUserId, 
                Resource = rolePermission.SecurableId,
                Action = rolePermission.PermissionId, 
                BranchId = bankUserRole.BranchId,
                RegionalOfficeId = bankUserRole.RegionalOfficeId,
                OfficeId = bankUserRole.OfficeId
            };
    }

    protected IQueryable<RolePolicyRule> GetRolePolicyRules()
    {
        return from bankUserRole in _context.BankUserRoles
            join role in _context.Roles on bankUserRole.RoleId equals role.Id
            where bankUserRole.EndDate == null || bankUserRole.EndDate > _dateService.UtcNow
            select new RolePolicyRule
            {
                UserId = (long) bankUserRole.BankUserId, 
                RoleName = role.Name, 
            };
    }
}