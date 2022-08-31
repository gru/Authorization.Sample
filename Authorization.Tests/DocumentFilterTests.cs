using System;
using System.Linq;
using Authorization.Sample.Entities;
using Authorization.Sample.Implementation;
using Authorization.Sample.Services;
using Casbin;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Authorization.Tests;

public class DocumentFilterTests
{
    [Fact]
    public void EnforceFilter_BankUser_Permissions()
    {
        var (enforcer, context) = CreateEnforcer(BankUserId.BankUser);

        var documents = enforcer.EnforceFilter(context.Documents, new DefaultFilterRequest()).ToArray();
        
        Assert.Equal(3, documents.Length);
        Assert.All(documents, d => Assert.Equal(DocumentTypeId.Account, d.DocumentTypeId));
    }
    
    [Fact]
    public void EnforceFilter_BankUser_Change_Permissions()
    {
        var (enforcer, context) = CreateEnforcer(BankUserId.BankUser);

        var accountForChange = enforcer.EnforceFilter(context.Documents, new DefaultFilterRequest(permissionId: PermissionId.Change)).ToArray();
        
        Assert.Equal(3, accountForChange.Length);
        Assert.All(accountForChange, d => Assert.Equal(DocumentTypeId.Account, d.DocumentTypeId));

        var accountsForDelete = enforcer.EnforceFilter(context.Documents, new DefaultFilterRequest(permissionId: PermissionId.Delete)).ToArray();
        Assert.Empty(accountsForDelete);
    }

    [Fact]
    public void EnforceFilter_RegionalOfficeUser_With_OrgContext()
    {
        var (enforcer, context) = CreateEnforcer(BankUserId.RegionalOfficeUser);
        
        var rootDocuments = enforcer.EnforceFilter(context.Documents, new DefaultFilterRequest()).ToArray();
        
        Assert.Empty(rootDocuments);

        var branchDocuments = enforcer.EnforceFilter(context.Documents, 
            new DefaultFilterRequest(new OrganizationContext(OrgIds.BranchId))).ToArray();

        Assert.Empty(branchDocuments);
        
        var regionalOfficeDocuments = enforcer.EnforceFilter(context.Documents, 
            new DefaultFilterRequest(new OrganizationContext(OrgIds.BranchId, OrgIds.RegionalOfficeId))).ToArray();
        
        Assert.Equal(3, regionalOfficeDocuments.Length);
        Assert.All(regionalOfficeDocuments, d => Assert.Equal(OrgIds.BranchId, d.BranchId));
        
        var officeDocuments = enforcer.EnforceFilter(context.Documents, 
            new DefaultFilterRequest(new OrganizationContext(OrgIds.BranchId, OrgIds.RegionalOfficeId, OrgIds.OfficeId))).ToArray();

        Assert.Equal(2, officeDocuments.Length);
        Assert.All(officeDocuments, d => Assert.Equal(OrgIds.OfficeId, d.OfficeId));
    }
    
    [Fact]
    public void EnforceFilter_OfficeUser_With_OrgContext()
    {
        var (enforcer, context) = CreateEnforcer(BankUserId.OfficeUser);
        
        var rootDocuments = enforcer.EnforceFilter(context.Documents).ToArray();
        
        Assert.Empty(rootDocuments);

        var branchDocuments = enforcer.EnforceFilter(context.Documents, 
            new DefaultFilterRequest(new OrganizationContext(OrgIds.BranchId))).ToArray();

        Assert.Empty(branchDocuments);
        
        var regionalOfficeDocuments = enforcer.EnforceFilter(context.Documents, 
            new DefaultFilterRequest(new OrganizationContext(OrgIds.BranchId, OrgIds.RegionalOfficeId))).ToArray();
        
        Assert.Empty(regionalOfficeDocuments);
        
        var officeDocuments = enforcer.EnforceFilter(context.Documents, 
            new DefaultFilterRequest(new OrganizationContext(OrgIds.BranchId, OrgIds.RegionalOfficeId, OrgIds.OfficeId))).ToArray();

        Assert.Equal(2, officeDocuments.Length);
        Assert.All(officeDocuments, d => Assert.Equal(OrgIds.OfficeId, d.OfficeId));
    }
    
    [Fact]
    public void Enforce_Supervisor_Permissions()
    {
        var (enforcer, context) = CreateEnforcer(BankUserId.Supervisor);

        var documents = enforcer.EnforceFilter(context.Documents).ToArray();
        Assert.Equal(5, documents.Length);
    }
    
    [Theory]
    [ClassData(typeof(OrgStructureClassData))]
    public void Enforce_Supervisor_Permissions_With_OrgContext(OrganizationContext organizationContext)
    {
        var (enforcer, context) = CreateEnforcer(BankUserId.Supervisor);

        var documents = enforcer.EnforceFilter(context.Documents, new DefaultFilterRequest( organizationContext)).ToArray();
        Assert.Equal(5, documents.Length);
    }
    
    private static (AuthorizationEnforcer, DataContext) CreateEnforcer(BankUserId currentUser)
    {
        var serviceCollection = new ServiceCollection();
        var dataContext = ServiceCollectionEx.GetInMemoryDataContext();
        serviceCollection.AddInMemoryDataContext(dataContext);
        serviceCollection.AddSingleton(new CasbinAuthorizationModelOptions());
        serviceCollection.AddSingleton<ICurrentUserService>(new TestCurrentUserService(currentUser));
        serviceCollection.AddSingleton<ICurrentDateService>(new TestCurrentDateService(DateTimeOffset.Now));
        serviceCollection.AddSingleton<IDemoService>(new DemoService(false));
        serviceCollection.AddSingleton<IAuthorizationModelFactory<IEnforcer>, CasbinAuthorizationModelFactory>();
        serviceCollection.AddSingleton<IMatcher<ResourceAuthorizationRequest>, ResourceCasbinMatcher>();
        serviceCollection.AddSingleton<IMatcher<DocumentAuthorizationRequest>, DocumentCasbinMatcher>();
        serviceCollection.AddSingleton<IFilter<Document, DefaultFilterRequest>, DocumentCasbinFilter>();
        serviceCollection.AddSingleton<AuthorizationEnforcer>();

        var enforcer = serviceCollection.BuildServiceProvider().GetService<AuthorizationEnforcer>(); 
        
        return (enforcer, dataContext);
    }
}