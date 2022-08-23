using System;
using System.Linq;
using Authorization.Sample;
using Authorization.Tests.Entities;
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
    
    private static Enforcer CreateEnforcer(BankUserId currentUser)
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddSingleton(new DataContext());
        serviceCollection.AddSingleton<ICurrentUserService>(new TestUserService(currentUser));
        serviceCollection.AddSingleton<ICurrentDateService>(new TestCurrentDateService(DateTimeOffset.Now));
        serviceCollection.AddSingleton<IPolicyRuleQuery<ResourcePolicyRule>, ResourcePolicyRuleQuery>();
        serviceCollection.AddSingleton<IPolicyRuleQuery<RolePolicyRule>, RolePolicyRuleQuery>();
        serviceCollection.AddSingleton<IMatcher<ResourceAuthorizationRequest>, ResourcePermissionMatcher>();
        serviceCollection.AddSingleton<IMatcher<ResourceAuthorizationRequest>, SuperuserMatcher>();
        serviceCollection.AddSingleton<IPolicyRuleQuery<DocumentPolicyRule>, DocumentPolicyRuleQuery>();
        serviceCollection.AddSingleton<IMatcher<DocumentAuthorizationRequest>, DocumentMatcher>();
        serviceCollection.AddSingleton<IMatcher<DocumentAuthorizationRequest>, DocumentSuperuserMatcher>();
        serviceCollection.AddSingleton<IFilter<Document, DocumentFilterRequest>, DocumentFilter>();
        serviceCollection.AddSingleton<IFilter<Document, DocumentFilterRequest>, SuperuserFilter>();
        serviceCollection.AddSingleton<IFilter<Document, DocumentFilterRequest>, SupervisorDocumentFilter>();
        serviceCollection.AddSingleton<Enforcer>();

        return serviceCollection.BuildServiceProvider().GetService<Enforcer>();
    }
}

public class SuperuserFilter : Filter<Document, DocumentFilterRequest, RolePolicyRule>
{
    public SuperuserFilter(IPolicyRuleQuery<RolePolicyRule> rules) 
        : base(rules)
    {
    }

    protected override IQueryable<Document> Apply(IQueryable<Document> query, DocumentFilterRequest context, IQueryable<RolePolicyRule> rules)
    {
        var resultQuery = from document in query
            where rules.Any(r => r.UserId == context.UserId && r.RoleName == "Superuser")
            select document;

        return resultQuery;
    }
}

public class SupervisorDocumentFilter : Filter<Document, DocumentFilterRequest, ResourcePolicyRule>
{
    public SupervisorDocumentFilter(IPolicyRuleQuery<ResourcePolicyRule> rules) 
        : base(rules)
    {
    }

    protected override IQueryable<Document> Apply(IQueryable<Document> query, DocumentFilterRequest context, IQueryable<ResourcePolicyRule> rules)
    {
        var resultQuery = from document in query
            where rules.Any(r => r.UserId == context.UserId &&
                                 r.Action == PermissionId.Any &&
                                 (r.Resource == SecurableId.Document || r.Resource == SecurableId.Any))
            select document;

        return resultQuery;
    }
}

public interface IDocumentAuthorizationRequest
{
    long UserId { get; }
    
    PermissionId PermissionId { get; }
    
    OrganizationContext OrganizationContext { get; }
}

public class DocumentFilterRequest : ICurrentUserAuthorizationRequest, IDocumentAuthorizationRequest
{
    public DocumentFilterRequest(OrganizationContext organizationContext = null, PermissionId permissionId = PermissionId.View)
    {
        PermissionId = permissionId;
        OrganizationContext = organizationContext;
    }

    public long UserId { get; set; }
    
    public PermissionId PermissionId { get; }
    
    public OrganizationContext OrganizationContext { get; }
}

public class DocumentFilter : Filter<Document, DocumentFilterRequest, DocumentPolicyRule>
{
    public DocumentFilter(IPolicyRuleQuery<DocumentPolicyRule> rules) 
        : base(rules)
    {
    }

    protected override IQueryable<Document> Apply(IQueryable<Document> query, DocumentFilterRequest request, IQueryable<DocumentPolicyRule> rules)
    {
        if (request.OrganizationContext != null)
        {
            query = query
                .Where(d => (d.BranchId == request.OrganizationContext.BranchId) &&
                            (d.OfficeId == request.OrganizationContext.OfficeId || request.OrganizationContext.OfficeId == null));
        }
        
        var resultQuery = query
            .Join(rules.ApplyFilters(request),
                d => d.DocumentTypeId,
                r => r.DocumentTypeId,
                (d, r) => new { Document = d, Rule = r })
            .Select(pair => pair.Document);

        return resultQuery;
    }
}

public static class DocumentPolicyRuleEx
{
    public static IQueryable<DocumentPolicyRule> ApplyFilters(
        this IQueryable<DocumentPolicyRule> queryable, IDocumentAuthorizationRequest request)
    {
        return queryable
            .ApplyOrganizationContextFilter(request.OrganizationContext)
            .Where(r => r.UserId == request.UserId &&
                       (r.PermissionId == PermissionId.Any || r.PermissionId == request.PermissionId));
    }
}