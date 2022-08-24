using System;
using System.Linq;
using Authorization.Sample.Entities;
using Authorization.Sample.Implementation;
using Authorization.Sample.Services;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Authorization.Tests;

public class DocumentEnforcerTests
{
    [Fact]
    public void Enforce_BankUser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.BankUser);
        
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.View)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.Change)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.View)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.Change)));
    }

    [Fact]
    public void Enforce_BankUser_Document_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.BankUser);
        
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(
            document: new Document { Id = 10, DocumentTypeId = DocumentTypeId.Account, BranchId = OrgStructure.BranchId, OfficeId = OrgStructure.OfficeId }, 
            permissionId: PermissionId.View)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(
            document: new Document { Id = 10, DocumentTypeId = DocumentTypeId.Account, BranchId = OrgStructure.BranchId, OfficeId = OrgStructure.OfficeId }, 
            permissionId: PermissionId.Delete)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(
            document: new Document { Id = 10, DocumentTypeId = DocumentTypeId.Guarantee, BranchId = OrgStructure.BranchId, OfficeId = OrgStructure.OfficeId }, 
            permissionId: PermissionId.View)));
    }
    
    [Fact]
    public void Enforce_OfficeUser_Document_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.OfficeUser);
        
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(
            document: new Document { Id = 10, DocumentTypeId = DocumentTypeId.Account, BranchId = OrgStructure.BranchId, OfficeId = OrgStructure.OfficeId }, 
            permissionId: PermissionId.View)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(
            document: new Document { Id = 10, DocumentTypeId = DocumentTypeId.Account, BranchId = OrgStructure.BranchId, OfficeId = 100 }, 
            permissionId: PermissionId.View)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(
            document: new Document { Id = 10, DocumentTypeId = DocumentTypeId.Account, BranchId = 100, OfficeId = OrgStructure.OfficeId }, 
            permissionId: PermissionId.View)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(
            document: new Document { Id = 10, DocumentTypeId = DocumentTypeId.Account, BranchId = OrgStructure.BranchId, OfficeId = OrgStructure.OfficeId }, 
            permissionId: PermissionId.Delete)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(
            document: new Document { Id = 10, DocumentTypeId = DocumentTypeId.Guarantee, BranchId = OrgStructure.BranchId, OfficeId = OrgStructure.OfficeId }, 
            permissionId: PermissionId.View)));
    }
    
    [Fact]
    public void Enforce_BranchUser_Permissions_With_Org_Context()
    {
        var enforcer = CreateEnforcer(BankUserId.BranchUser);
        
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.View)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.Change)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.View)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.Change)));

        var data = new OrgStructureClassData();
        foreach (var organizationContext in data.EnumerateContexts())
        {
            Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.View, organizationContext)));
            Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.Change, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.View, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.Change, organizationContext)));
        }
    }
    
    [Fact]
    public void Enforce_RegionalOfficeUser_Permissions_With_Org_Context()
    {
        var enforcer = CreateEnforcer(BankUserId.RegionalOfficeUser);
        
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.View)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.Change)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.View)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.Change)));
        
        var data = new OrgStructureClassData();
        foreach (var organizationContext in data.EnumerateContexts().Take(OrgContextCount.BranchTakeCount))
        {
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.View, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.Change, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.View, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.Change, organizationContext)));
        }
        
        foreach (var organizationContext in data.EnumerateContexts().Skip(OrgContextCount.RegionalOfficeSkipCount))
        {
            Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.View, organizationContext)));
            Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.Change, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.View, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.Change, organizationContext)));
        }
    }
    
    [Fact]
    public void Enforce_OfficeUser_Permissions_With_Org_Context()
    {
        var enforcer = CreateEnforcer(BankUserId.OfficeUser);
        
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.View)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.Change)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.View)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.Change)));
        
        var data = new OrgStructureClassData();
        foreach (var organizationContext in data.EnumerateContexts().Take(OrgContextCount.RegionalOfficeTakeCount))
        {
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.View, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.Change, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.View, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.Change, organizationContext)));
        }
        
        foreach (var organizationContext in data.EnumerateContexts().Skip(OrgContextCount.OfficeSkipCount))
        {
            Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.View, organizationContext)));
            Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.Change, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.View, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.Change, organizationContext)));
        }
    }
    
    [Fact]
    public void Enforce_Superuser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.View)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.Change)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.View)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.Change)));
    }

    [Theory]
    [ClassData(typeof(OrgStructureClassData))]
    public void Enforce_Superuser_Permissions_With_OrgContext(OrganizationContext organizationContext)
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.View, organizationContext)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.Change, organizationContext)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.View, organizationContext)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.Change, organizationContext)));
    }
    
    [Fact]
    public void Enforce_Supervisor_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Supervisor);
        
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.View)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.Change)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.View)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.Change)));
    }
    
    [Theory]
    [ClassData(typeof(OrgStructureClassData))]
    public void Enforce_Supervisor_Permissions_With_OrgContext(OrganizationContext organizationContext)
    {
        var enforcer = CreateEnforcer(BankUserId.Supervisor);
        
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.View, organizationContext)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, PermissionId.Change, organizationContext)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.View, organizationContext)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, PermissionId.Change, organizationContext)));
    }
    
    private static AuthorizationEnforcer CreateEnforcer(BankUserId currentUser)
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddInMemoryDataContext();
        serviceCollection.AddSingleton<ICurrentUserService>(new TestCurrentUserService(currentUser));
        serviceCollection.AddSingleton<IDemoService>(new DemoService(false));
        serviceCollection.AddSingleton<ICurrentDateService>(new TestCurrentDateService(DateTimeOffset.Now));
        serviceCollection.AddSingleton<IAuthorizationModelFactory<ResourceAuthorizationModel>, ResourceAuthorizationModelFactory>();
        serviceCollection.AddSingleton<IAuthorizationModelFactory<DocumentAuthorizationModel>, DocumentAuthorizationModelFactory>();
        serviceCollection.AddSingleton<IMatcher<ResourceAuthorizationRequest>, ResourcePermissionMatcher>();
        serviceCollection.AddSingleton<IMatcher<DocumentAuthorizationRequest>, DocumentMatcher>();
        serviceCollection.AddSingleton<AuthorizationEnforcer>();

        return serviceCollection.BuildServiceProvider().GetService<AuthorizationEnforcer>();
    }
}