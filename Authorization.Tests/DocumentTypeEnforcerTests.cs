using System.Linq;
using Authorization.Sample;
using Authorization.Tests.Entities;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Authorization.Tests;

public class DocumentTypeEnforcerTests
{
    [Fact]
    public void Enforce_BankUser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.BankUser);
        
        Assert.True(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Account, Permissions.View)));
        Assert.False(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Account, Permissions.Change)));
        Assert.False(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.View)));
        Assert.False(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.Change)));
    }

    [Fact]
    public void Enforce_Superuser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        
        Assert.True(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Account, Permissions.View)));
        Assert.True(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Account, Permissions.Change)));
        Assert.True(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.View)));
        Assert.True(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.Change)));
    }
    
    [Fact]
    public void Enforce_Supervisor_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Superuser);
        
        Assert.True(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Account, Permissions.View)));
        Assert.True(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Account, Permissions.Change)));
        Assert.True(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.View)));
        Assert.True(enforcer.Enforce(new DocumentTypeAuthorizationRequest(DocumentTypeId.Guarantee, Permissions.Change)));
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
        serviceCollection.AddSingleton<IMatcher<DocumentTypeAuthorizationRequest>, DocumentTypeSupervisorMatcher>();
        serviceCollection.AddSingleton<Enforcer>();

        return serviceCollection.BuildServiceProvider().GetService<Enforcer>();
    }
}


public class DocumentTypePolicyRule
{
    public long UserId { get; set; }

    public DocumentTypeId DocumentTypeId { get; set; }

    public PermissionId PermissionId { get; set; }
}

public class DocumentTypePolicyRuleQuery : IPolicyRuleQuery<DocumentTypePolicyRule>
{
    private readonly DataContext _context;

    public DocumentTypePolicyRuleQuery(DataContext context)
    {
        _context = context;
    }
    
    public IQueryable<DocumentTypePolicyRule> PrepareQuery()
    {
        var query =
            from bankUserRole in _context.BankUserRoles
            join documentTypeRolePermission in _context.DocumentTypeRolePermissions on bankUserRole.RoleId equals documentTypeRolePermission.RoleId
            select new DocumentTypePolicyRule
            { 
                UserId = (long) bankUserRole.BankUserId,
                DocumentTypeId = documentTypeRolePermission.DocumentTypeId,
                PermissionId = documentTypeRolePermission.PermissionId,
            };

        return query;
    }
}

public class DocumentTypeMatcher : Matcher<DocumentTypeAuthorizationRequest, DocumentTypePolicyRule>
{
    public DocumentTypeMatcher(IPolicyRuleQuery<DocumentTypePolicyRule> policyRuleQuery) 
        : base(policyRuleQuery)
    {
    }

    protected override IQueryable<PolicyEffect> Match(DocumentTypeAuthorizationRequest request, IQueryable<DocumentTypePolicyRule> rules)
    {
        return rules
            .Where(r => r.UserId == request.UserId && 
                       (r.PermissionId == request.PermissionId || r.PermissionId == PermissionId.Any) && 
                       (r.DocumentTypeId == request.DocumentTypeId))
            .Select(r => PolicyEffect.Allow);
    }
}

public class DocumentTypeSuperuserMatcher : SuperuserMatcherBase<DocumentTypeAuthorizationRequest>
{
    public DocumentTypeSuperuserMatcher(IPolicyRuleQuery<RolePolicyRule> policyRuleQuery) 
        : base(policyRuleQuery)
    {
    }

    protected override IQueryable<PolicyEffect> Match(DocumentTypeAuthorizationRequest request, IQueryable<RolePolicyRule> rules)
    {
        return Match(request.UserId, rules);
    }
}

public class DocumentTypeSupervisorMatcher : Matcher<DocumentTypeAuthorizationRequest, ResourcePolicyRule>
{
    public DocumentTypeSupervisorMatcher(IPolicyRuleQuery<ResourcePolicyRule> policyRuleQuery) 
        : base(policyRuleQuery)
    {
    }

    protected override IQueryable<PolicyEffect> Match(DocumentTypeAuthorizationRequest request, IQueryable<ResourcePolicyRule> rules)
    {
        return rules
            .Where(r => r.UserId == request.UserId &&
                       (r.Resource == SecurableId.Document || r.Resource == SecurableId.Any) &&
                        r.Action == PermissionId.Any)
            .Select(r => PolicyEffect.Allow);
    }
}

public class DocumentTypeAuthorizationRequest : CurrentUserAuthorizationRequest
{
    public DocumentTypeAuthorizationRequest(DocumentTypeId documentTypeId, PermissionId permissionId)
    {
        DocumentTypeId = documentTypeId;
        PermissionId = permissionId;
    }

    public DocumentTypeId DocumentTypeId { get; set; }

    public PermissionId PermissionId { get; set; }
}