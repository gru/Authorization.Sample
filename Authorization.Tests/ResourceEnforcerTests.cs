using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using Authorization.Sample.Entities;
using Authorization.Sample.Implementation;
using Authorization.Sample.Services;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Authorization.Tests;

public class ResourceEnforcerTests
{
    [Fact]
    public void Enforce_BankUser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.BankUser);

        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.View)));
        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.Change)));
    }

    [Fact]
    public void Enforce_BranchUser_Permissions_With_OrgContext()
    {
        var enforcer = CreateEnforcer(BankUserId.BranchUser);

        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.View)));
        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.Change)));

        var data = new OrgStructureClassData();
        foreach (var organizationContext in data.EnumerateContexts())
        {
            Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.View, organizationContext)));
            Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.Change, organizationContext)));
        }
    }
    
    [Fact]
    public void Enforce_RegionalOfficeUser_Permissions_With_OrgContext()
    {
        var enforcer = CreateEnforcer(BankUserId.RegionalOfficeUser);

        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.View)));
        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.Change)));

        var data = new OrgStructureClassData();
        foreach (var organizationContext in data.EnumerateContexts().Take(OrgContextCount.BranchTakeCount))
        {
            Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.View, organizationContext)));
            Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.Change, organizationContext)));
        }
        
        foreach (var organizationContext in data.EnumerateContexts().Skip(OrgContextCount.RegionalOfficeSkipCount))
        {
            Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.View, organizationContext)));
            Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.Change, organizationContext)));
        }
    }
    
    [Fact]
    public void Enforce_OfficeUser_Permissions_With_OrgContext()
    {
        var enforcer = CreateEnforcer(BankUserId.OfficeUser);

        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.View)));
        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.Change)));

        var data = new OrgStructureClassData();
        foreach (var organizationContext in data.EnumerateContexts().Take(OrgContextCount.RegionalOfficeTakeCount))
        {
            Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.View, organizationContext)));
            Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.Change, organizationContext)));
        }
        
        foreach (var organizationContext in data.EnumerateContexts().Skip(OrgContextCount.OfficeSkipCount))
        {
            Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.View, organizationContext)));
            Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.Change, organizationContext)));
        }
    }
    
    [Fact]
    public void Enforce_Superuser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.View)));
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.Change)));
    }

    [Theory]
    [ClassData(typeof(OrgStructureClassData))]
    public void Enforce_Superuser_Permissions_With_OrgContext(OrganizationContext organizationContext)
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.View, organizationContext)));
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.Change, organizationContext)));
    }

    [Fact]
    public void Enforce_Supervisor_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Supervisor);
        
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.View)));
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.Change)));
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.DocumentationFile, PermissionId.Change)));
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.DocumentationFile, PermissionId.Delete)));
    }
    
    [Theory]
    [ClassData(typeof(OrgStructureClassData))]
    public void Enforce_Supervisor_Permissions_With_OrgContext(OrganizationContext organizationContext)
    {
        var enforcer = CreateEnforcer(BankUserId.Supervisor);
        
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.View, organizationContext)));
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.Change, organizationContext)));
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.DocumentationFile, PermissionId.Change, organizationContext)));
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.DocumentationFile, PermissionId.Delete, organizationContext)));
    }
    
    [Fact]
    public void Enforce_Supervisor_Permissions_Demo()
    {
        var enforcer = CreateEnforcer(BankUserId.Supervisor, true);
    
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.View)));
        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.Change)));
        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.DocumentationFile, PermissionId.Change)));
        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.DocumentationFile, PermissionId.Delete)));
    }
    
    [Fact]
    public void Enforce_Superuser_Permissions_Demo()
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser, true);
    
        Assert.True(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.View)));
        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.Document, PermissionId.Change)));
        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.DocumentationFile, PermissionId.Change)));
        Assert.False(enforcer.Enforce(new ResourceAuthorizationRequest(Securables.DocumentationFile, PermissionId.Delete)));
    }
    
    private static AuthorizationEnforcer CreateEnforcer(BankUserId currentUser, bool demo = false)
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddInMemoryDataContext();
        serviceCollection.AddSingleton<ICurrentUserService>(new TestCurrentUserService(currentUser));
        serviceCollection.AddSingleton<ICurrentDateService>(new TestCurrentDateService(DateTimeOffset.Now));
        serviceCollection.AddSingleton<IDemoService>(new DemoService(demo));
        serviceCollection.AddSingleton<IAuthorizationModelFactory<ResourceAuthorizationModel>, ResourceAuthorizationModelFactory>();
        serviceCollection.AddSingleton<IMatcher<ResourceAuthorizationRequest>, ResourcePermissionMatcher>();
        serviceCollection.AddSingleton<AuthorizationEnforcer>();

        return serviceCollection.BuildServiceProvider().GetService<AuthorizationEnforcer>();
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
        yield return new object[] { new OrganizationContext(OrgIds.BranchId) };
        yield return new object[] { new OrganizationContext(OrgIds.BranchId, OrgIds.RegionalOfficeId) };
        yield return new object[] { new OrganizationContext(OrgIds.BranchId, OrgIds.RegionalOfficeId, OrgIds.OfficeId) };
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