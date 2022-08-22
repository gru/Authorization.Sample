using System.Linq;
using Authorization.Sample;
using Authorization.Tests.Entities;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Authorization.Tests;

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
    public void EnforceFilter_BankUser_Change_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.BankUser);
        var context = new DataContext();

        var accountForChange = enforcer.EnforceFilter(context.Documents, permissionId: PermissionId.Change).ToArray();
        
        Assert.Equal(2, accountForChange.Length);
        Assert.All(accountForChange, d => Assert.Equal(d.DocumentTypeId, DocumentTypeId.Account));

        var accountsForDelete = enforcer.EnforceFilter(context.Documents, permissionId: PermissionId.Delete).ToArray();
        Assert.Empty(accountsForDelete);
    }

    [Fact]
    public void EnforceFilter_RegionalOfficeUser_With_OrgContext()
    {
        var enforcer = CreateEnforcer(BankUserId.RegionalOfficeUser);
        var context = new DataContext();

        var rootDocuments = enforcer.EnforceFilter(context.Documents).ToArray();
        
        Assert.Empty(rootDocuments);

        var data = new OrgStructureClassData();
        foreach (var organizationContext in data.EnumerateContexts().Take(OrgContextCount.BranchTakeCount))
        {
            var documents = enforcer.EnforceFilter(context.Documents, organizationContext).ToArray();
            
            Assert.Empty(documents);
        }

        foreach (var organizationContext in data.EnumerateContexts().Skip(OrgContextCount.RegionalOfficeSkipCount))
        {
            var documents = enforcer.EnforceFilter(context.Documents, organizationContext).ToArray();
            
            Assert.Equal(2, documents.Length);
            Assert.All(documents, d => Assert.Equal(d.DocumentTypeId, DocumentTypeId.Account));
        }
    }

    
    [Fact]
    public void EnforceFilter_OfficeUser_With_OrgContext()
    {
        var enforcer = CreateEnforcer(BankUserId.OfficeUser);
        var context = new DataContext();

        var rootDocuments = enforcer.EnforceFilter(context.Documents).ToArray();
        
        Assert.Empty(rootDocuments);

        var data = new OrgStructureClassData();
        foreach (var organizationContext in data.EnumerateContexts().Take(OrgContextCount.RegionalOfficeTakeCount))
        {
            var documents = enforcer.EnforceFilter(context.Documents, organizationContext).ToArray();
            
            Assert.Empty(documents);
        }

        foreach (var organizationContext in data.EnumerateContexts().Skip(OrgContextCount.OfficeSkipCount))
        {
            var documents = enforcer.EnforceFilter(context.Documents, organizationContext).ToArray();
            
            Assert.Equal(2, documents.Length);
            Assert.All(documents, d => Assert.Equal(d.DocumentTypeId, DocumentTypeId.Account));
        }
    }
    
    [Fact]
    public void Enforce_Superuser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        var context = new DataContext();

        var documents = enforcer.EnforceFilter(context.Documents).ToArray();
        Assert.Equal(3, documents.Length);
    }
    
    [Theory]
    [ClassData(typeof(OrgStructureClassData))]
    public void Enforce_Superuser_Permissions_With_OrgContext(OrganizationContext organizationContext)
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        var context = new DataContext();

        var documents = enforcer.EnforceFilter(context.Documents, organizationContext).ToArray();
        Assert.Equal(3, documents.Length);
    }
    
    [Fact]
    public void Enforce_Supervisor_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Supervisor);
        var context = new DataContext();

        var documents = enforcer.EnforceFilter(context.Documents).ToArray();
        Assert.Equal(3, documents.Length);
    }
    
    [Theory]
    [ClassData(typeof(OrgStructureClassData))]
    public void Enforce_Supervisor_Permissions_With_OrgContext(OrganizationContext organizationContext)
    {
        var enforcer = CreateEnforcer(BankUserId.Supervisor);
        var context = new DataContext();

        var documents = enforcer.EnforceFilter(context.Documents, organizationContext).ToArray();
        Assert.Equal(3, documents.Length);
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
        serviceCollection.AddSingleton<IPolicyRuleQuery<DocumentTypePolicyRule>, DocumentTypePolicyRuleQuery>();
        serviceCollection.AddSingleton<IMatcher<DocumentTypeAuthorizationRequest>, DocumentTypeMatcher>();
        serviceCollection.AddSingleton<IMatcher<DocumentTypeAuthorizationRequest>, DocumentTypeSuperuserMatcher>();
        serviceCollection.AddSingleton<IFilter<Document, AuthorizationFilterContext>, DocumentTypeFilter>();
        serviceCollection.AddSingleton<IFilter<Document, AuthorizationFilterContext>, SuperuserFilter>();
        serviceCollection.AddSingleton<IFilter<Document, AuthorizationFilterContext>, SupervisorDocumentFilter>();
        serviceCollection.AddSingleton<Enforcer>();

        return serviceCollection.BuildServiceProvider().GetService<Enforcer>();
    }
}

public class SuperuserFilter : Filter<Document, RolePolicyRule>
{
    public SuperuserFilter(IPolicyRuleQuery<RolePolicyRule> rules) 
        : base(rules)
    {
    }

    protected override IQueryable<Document> Apply(IQueryable<Document> query, AuthorizationFilterContext context, IQueryable<RolePolicyRule> rules)
    {
        var resultQuery = from document in query
            where rules.Any(r => r.UserId == context.UserId && r.RoleName == "Superuser")
            select document;

        return resultQuery;
    }
}

public class SupervisorDocumentFilter : Filter<Document, ResourcePolicyRule>
{
    public SupervisorDocumentFilter(IPolicyRuleQuery<ResourcePolicyRule> rules) 
        : base(rules)
    {
    }

    protected override IQueryable<Document> Apply(IQueryable<Document> query, AuthorizationFilterContext context, IQueryable<ResourcePolicyRule> rules)
    {
        var resultQuery = from document in query
            where rules.Any(r => r.UserId == context.UserId && (r.Resource == SecurableId.Document || r.Resource == SecurableId.Any) && r.Action == PermissionId.Any)
            select document;

        return resultQuery;
    }
}

public class DocumentTypeFilter : Filter<Document, DocumentTypePolicyRule>
{
    public DocumentTypeFilter(IPolicyRuleQuery<DocumentTypePolicyRule> rules) 
        : base(rules)
    {
    }

    protected override IQueryable<Document> Apply(IQueryable<Document> query, AuthorizationFilterContext context, IQueryable<DocumentTypePolicyRule> rules)
    {
        var organizationContextRules = rules
            .ApplyOrganizationContextFilter(context.OrganizationContext);
        
        var resultQuery = query
            .Join(organizationContextRules, d => d.DocumentTypeId, r => r.DocumentTypeId,
                (d, r) => new { Document = d, Rule = r })
            .Where(pair => pair.Rule.UserId == context.UserId && pair.Rule.PermissionId == context.PermissionId)
            .Select(pair => pair.Document);

        return resultQuery;
    }
}