using System;
using System.Linq;
using Authorization.Sample.Entities;
using Authorization.Sample.Implementation;
using Authorization.Sample.Services;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Authorization.Tests;

public class DocumentFilterTests
{
    [Fact]
    public void EnforceFilter_BankUser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.BankUser);
        var context = new DataContext();

        var documents = enforcer.EnforceFilter(context.Documents, new DocumentFilterRequest()).ToArray();
        
        Assert.Equal(3, documents.Length);
        Assert.All(documents, d => Assert.Equal(DocumentTypeId.Account, d.DocumentTypeId));
    }
    
    [Fact]
    public void EnforceFilter_BankUser_Change_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.BankUser);
        var context = new DataContext();

        var accountForChange = enforcer.EnforceFilter(context.Documents, new DocumentFilterRequest(permissionId: PermissionId.Change)).ToArray();
        
        Assert.Equal(3, accountForChange.Length);
        Assert.All(accountForChange, d => Assert.Equal(DocumentTypeId.Account, d.DocumentTypeId));

        var accountsForDelete = enforcer.EnforceFilter(context.Documents, new DocumentFilterRequest(permissionId: PermissionId.Delete)).ToArray();
        Assert.Empty(accountsForDelete);
    }

    [Fact]
    public void EnforceFilter_RegionalOfficeUser_With_OrgContext()
    {
        var enforcer = CreateEnforcer(BankUserId.RegionalOfficeUser);
        var context = new DataContext();

        var rootDocuments = enforcer.EnforceFilter(context.Documents, new DocumentFilterRequest()).ToArray();
        
        Assert.Empty(rootDocuments);

        var branchDocuments = enforcer.EnforceFilter(context.Documents, 
            new DocumentFilterRequest(new OrganizationContext(OrgStructure.BranchId))).ToArray();

        Assert.Empty(branchDocuments);
        
        var regionalOfficeDocuments = enforcer.EnforceFilter(context.Documents, 
            new DocumentFilterRequest(new OrganizationContext(OrgStructure.BranchId, OrgStructure.RegionalOfficeId))).ToArray();
        
        Assert.Equal(3, regionalOfficeDocuments.Length);
        Assert.All(regionalOfficeDocuments, d => Assert.Equal(OrgStructure.BranchId, d.BranchId));
        
        var officeDocuments = enforcer.EnforceFilter(context.Documents, 
            new DocumentFilterRequest(new OrganizationContext(OrgStructure.BranchId, OrgStructure.RegionalOfficeId, OrgStructure.OfficeId))).ToArray();

        Assert.Equal(2, officeDocuments.Length);
        Assert.All(officeDocuments, d => Assert.Equal(OrgStructure.OfficeId, d.OfficeId));
    }
    
    [Fact]
    public void EnforceFilter_OfficeUser_With_OrgContext()
    {
        var enforcer = CreateEnforcer(BankUserId.OfficeUser);
        var context = new DataContext();

        var rootDocuments = enforcer.EnforceFilter(context.Documents, new DocumentFilterRequest()).ToArray();
        
        Assert.Empty(rootDocuments);

        var branchDocuments = enforcer.EnforceFilter(context.Documents, 
            new DocumentFilterRequest(new OrganizationContext(OrgStructure.BranchId))).ToArray();

        Assert.Empty(branchDocuments);
        
        var regionalOfficeDocuments = enforcer.EnforceFilter(context.Documents, 
            new DocumentFilterRequest(new OrganizationContext(OrgStructure.BranchId, OrgStructure.RegionalOfficeId))).ToArray();
        
        Assert.Empty(regionalOfficeDocuments);
        
        var officeDocuments = enforcer.EnforceFilter(context.Documents, 
            new DocumentFilterRequest(new OrganizationContext(OrgStructure.BranchId, OrgStructure.RegionalOfficeId, OrgStructure.OfficeId))).ToArray();

        Assert.Equal(2, officeDocuments.Length);
        Assert.All(officeDocuments, d => Assert.Equal(OrgStructure.OfficeId, d.OfficeId));
    }
    
    [Fact]
    public void Enforce_Superuser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        var context = new DataContext();

        var documents = enforcer.EnforceFilter(context.Documents, new DocumentFilterRequest()).ToArray();
        Assert.Equal(5, documents.Length);
    }
    
    [Theory]
    [ClassData(typeof(OrgStructureClassData))]
    public void Enforce_Superuser_Permissions_With_OrgContext(OrganizationContext organizationContext)
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        var context = new DataContext();

        var documents = enforcer.EnforceFilter(context.Documents, new DocumentFilterRequest(organizationContext)).ToArray();
        Assert.Equal(5, documents.Length);
    }
    
    [Fact]
    public void Enforce_Supervisor_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Supervisor);
        var context = new DataContext();

        var documents = enforcer.EnforceFilter(context.Documents, new DocumentFilterRequest()).ToArray();
        Assert.Equal(5, documents.Length);
    }
    
    [Theory]
    [ClassData(typeof(OrgStructureClassData))]
    public void Enforce_Supervisor_Permissions_With_OrgContext(OrganizationContext organizationContext)
    {
        var enforcer = CreateEnforcer(BankUserId.Supervisor);
        var context = new DataContext();

        var documents = enforcer.EnforceFilter(context.Documents, new DocumentFilterRequest(organizationContext)).ToArray();
        Assert.Equal(5, documents.Length);
    }
    
    private static AuthorizationEnforcer CreateEnforcer(BankUserId currentUser)
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddSingleton(new DataContext());
        serviceCollection.AddSingleton<ICurrentUserService>(new TestCurrentUserService(currentUser));
        serviceCollection.AddSingleton<ICurrentDateService>(new TestCurrentDateService(DateTimeOffset.Now));
        serviceCollection.AddSingleton<IAuthorizationModelFactory<ResourceAuthorizationModel>, ResourceAuthorizationModelFactory>();
        serviceCollection.AddSingleton<IAuthorizationModelFactory<DocumentAuthorizationModel>, DocumentAuthorizationModelFactory>();
        serviceCollection.AddSingleton<IMatcher<ResourceAuthorizationRequest>, ResourcePermissionMatcher>();
        serviceCollection.AddSingleton<IMatcher<DocumentAuthorizationRequest>, DocumentMatcher>();
        serviceCollection.AddSingleton<IFilter<Document, DocumentFilterRequest>, DocumentFilter>();
        serviceCollection.AddSingleton<AuthorizationEnforcer>();

        return serviceCollection.BuildServiceProvider().GetService<AuthorizationEnforcer>();
    }
}