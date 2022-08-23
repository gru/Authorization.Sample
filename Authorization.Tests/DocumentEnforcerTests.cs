using System.Linq;
using Authorization.Sample;
using Authorization.Tests.Entities;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Authorization.Tests;

public class DocumentEnforcerTests
{
    [Fact]
    public void Enforce_BankUser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.BankUser);
        
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.View)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.Change)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.View)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.Change)));
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
        
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.View)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.Change)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.View)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.Change)));

        var data = new OrgStructureClassData();
        foreach (var organizationContext in data.EnumerateContexts())
        {
            Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.View, organizationContext)));
            Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.Change, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.View, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.Change, organizationContext)));
        }
    }
    
    [Fact]
    public void Enforce_RegionalOfficeUser_Permissions_With_Org_Context()
    {
        var enforcer = CreateEnforcer(BankUserId.RegionalOfficeUser);
        
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.View)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.Change)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.View)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.Change)));
        
        var data = new OrgStructureClassData();
        foreach (var organizationContext in data.EnumerateContexts().Take(OrgContextCount.BranchTakeCount))
        {
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.View, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.Change, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.View, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.Change, organizationContext)));
        }
        
        foreach (var organizationContext in data.EnumerateContexts().Skip(OrgContextCount.RegionalOfficeSkipCount))
        {
            Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.View, organizationContext)));
            Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.Change, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.View, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.Change, organizationContext)));
        }
    }
    
    [Fact]
    public void Enforce_OfficeUser_Permissions_With_Org_Context()
    {
        var enforcer = CreateEnforcer(BankUserId.OfficeUser);
        
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.View)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.Change)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.View)));
        Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.Change)));
        
        var data = new OrgStructureClassData();
        foreach (var organizationContext in data.EnumerateContexts().Take(OrgContextCount.RegionalOfficeTakeCount))
        {
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.View, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.Change, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.View, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.Change, organizationContext)));
        }
        
        foreach (var organizationContext in data.EnumerateContexts().Skip(OrgContextCount.OfficeSkipCount))
        {
            Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.View, organizationContext)));
            Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.Change, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.View, organizationContext)));
            Assert.False(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.Change, organizationContext)));
        }
    }
    
    [Fact]
    public void Enforce_Superuser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.View)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.Change)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.View)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.Change)));
    }

    [Theory]
    [ClassData(typeof(OrgStructureClassData))]
    public void Enforce_Superuser_Permissions_With_OrgContext(OrganizationContext organizationContext)
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.View, organizationContext)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.Change, organizationContext)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.View, organizationContext)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.Change, organizationContext)));
    }
    
    [Fact]
    public void Enforce_Supervisor_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Supervisor);
        
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.View)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.Change)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.View)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.Change)));
    }
    
    [Theory]
    [ClassData(typeof(OrgStructureClassData))]
    public void Enforce_Supervisor_Permissions_With_OrgContext(OrganizationContext organizationContext)
    {
        var enforcer = CreateEnforcer(BankUserId.Supervisor);
        
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.View, organizationContext)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Account, Permissions.Change, organizationContext)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.View, organizationContext)));
        Assert.True(enforcer.Enforce(new DocumentAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.Change, organizationContext)));
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
        serviceCollection.AddSingleton<IPolicyRuleQuery<DocumentPolicyRule>, DocumentPolicyRuleQuery>();
        serviceCollection.AddSingleton<IMatcher<DocumentAuthorizationRequest>, DocumentMatcher>();
        serviceCollection.AddSingleton<IMatcher<DocumentAuthorizationRequest>, DocumentSuperuserMatcher>();
        serviceCollection.AddSingleton<IMatcher<DocumentAuthorizationRequest>, DocumentSupervisorMatcher>();
        serviceCollection.AddSingleton<Enforcer>();

        return serviceCollection.BuildServiceProvider().GetService<Enforcer>();
    }
}


public class DocumentPolicyRule : IOrganizationContextPolicyRule
{
    public long UserId { get; set; }

    public DocumentTypeId DocumentTypeId { get; set; }

    public PermissionId PermissionId { get; set; }
    
    public long? BranchId { get; set; }
    
    public long? RegionalOfficeId { get; set; }
    
    public long? OfficeId { get; set; }
}

public class DocumentPolicyRuleQuery : IPolicyRuleQuery<DocumentPolicyRule>
{
    private readonly DataContext _context;

    public DocumentPolicyRuleQuery(DataContext context)
    {
        _context = context;
    }
    
    public IQueryable<DocumentPolicyRule> PrepareQuery()
    {
        var query =
            from bankUserRole in _context.BankUserRoles
            join documentTypeRolePermission in _context.DocumentTypeRolePermissions on bankUserRole.RoleId equals documentTypeRolePermission.RoleId
            select new DocumentPolicyRule
            { 
                UserId = (long) bankUserRole.BankUserId,
                DocumentTypeId = documentTypeRolePermission.DocumentTypeId,
                PermissionId = documentTypeRolePermission.PermissionId,
                BranchId = bankUserRole.BranchId,
                RegionalOfficeId = bankUserRole.RegionalOfficeId,
                OfficeId = bankUserRole.OfficeId
            };

        return query;
    }
}

public class DocumentMatcher : Matcher<DocumentAuthorizationRequest, DocumentPolicyRule>
{
    public DocumentMatcher(IPolicyRuleQuery<DocumentPolicyRule> policyRuleQuery) 
        : base(policyRuleQuery)
    {
    }

    protected override IQueryable<PolicyEffect> Match(DocumentAuthorizationRequest request, IQueryable<DocumentPolicyRule> rules)
    {
        return rules
            .ApplyFilters(request)
            .Where(r => r.DocumentTypeId == request.DocumentTypeId)
            .Select(r => PolicyEffect.Allow);
    }
}

public class DocumentSuperuserMatcher : SuperuserMatcherBase<DocumentAuthorizationRequest>
{
    public DocumentSuperuserMatcher(IPolicyRuleQuery<RolePolicyRule> policyRuleQuery) 
        : base(policyRuleQuery)
    {
    }

    protected override IQueryable<PolicyEffect> Match(DocumentAuthorizationRequest request, IQueryable<RolePolicyRule> rules)
    {
        return Match(request.UserId, rules);
    }
}

public class DocumentSupervisorMatcher : Matcher<DocumentAuthorizationRequest, ResourcePolicyRule>
{
    public DocumentSupervisorMatcher(IPolicyRuleQuery<ResourcePolicyRule> policyRuleQuery) 
        : base(policyRuleQuery)
    {
    }

    protected override IQueryable<PolicyEffect> Match(DocumentAuthorizationRequest request, IQueryable<ResourcePolicyRule> rules)
    {
        return rules
            .Where(r => r.UserId == request.UserId &&
                       (r.Resource == SecurableId.Document || r.Resource == SecurableId.Any) &&
                        r.Action == PermissionId.Any)
            .Select(r => PolicyEffect.Allow);
    }
}

public class DocumentAuthorizationRequest : CurrentUserAuthorizationRequest, IDocumentAuthorizationRequest
{
    public DocumentAuthorizationRequest(Document document, PermissionId permissionId)
    {
        PermissionId = permissionId;
        DocumentTypeId = document.DocumentTypeId;
        OrganizationContext = new OrganizationContext(document.BranchId, null, document.OfficeId);
    }
    
    public DocumentAuthorizationRequest(
        DocumentTypeId documentTypeId, PermissionId permissionId, OrganizationContext organizationContext = null)
    {
        DocumentTypeId = documentTypeId;
        PermissionId = permissionId;
        OrganizationContext = organizationContext;
    }

    public DocumentTypeId DocumentTypeId { get; }

    public PermissionId PermissionId { get; }

    public OrganizationContext OrganizationContext { get; }
}