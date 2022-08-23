using System;
using System.Collections.Generic;
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
        serviceCollection.AddSingleton<ICurrentDateService>(new TestCurrentDateService(DateTimeOffset.Now));
        serviceCollection.AddSingleton<IAuthorizationModelFactory<ResourceAuthorizationModel>, ResourceAuthorizationModelFactory>();
        serviceCollection.AddSingleton<IAuthorizationModelFactory<DocumentAuthorizationModel>, DocumentAuthorizationModelFactory>();
        serviceCollection.AddSingleton<IMatcher<ResourceAuthorizationRequest>, ResourcePermissionMatcher>();
        serviceCollection.AddSingleton<IMatcher<DocumentAuthorizationRequest>, DocumentMatcher>();
        serviceCollection.AddSingleton<Enforcer>();

        return serviceCollection.BuildServiceProvider().GetService<Enforcer>();
    }
}

public class DocumentPolicyRule : IOrganizationContextRule
{
    public long UserId { get; set; }

    public DocumentTypeId DocumentTypeId { get; set; }

    public PermissionId PermissionId { get; set; }
    
    public long? BranchId { get; set; }
    
    public long? RegionalOfficeId { get; set; }
    
    public long? OfficeId { get; set; }
}

public class DocumentAuthorizationModelFactory : ResourceAuthorizationModelFactory, IAuthorizationModelFactory<DocumentAuthorizationModel>
{
    private readonly DataContext _context;
    private readonly ICurrentDateService _dateService;

    public DocumentAuthorizationModelFactory(DataContext context, ICurrentDateService dateService) 
        : base(context, dateService)
    {
        _context = context;
        _dateService = dateService;
    }
    
    public new DocumentAuthorizationModel PrepareModel()
    {
        var model = new DocumentAuthorizationModel(
            GetResourcePolicyRules(), 
            GetRolePolicyRules(), 
            GetDocumentPolicyRules());
        
        return model;
    }

    protected IQueryable<DocumentPolicyRule> GetDocumentPolicyRules()
    {
        return from bankUserRole in _context.BankUserRoles
            join documentTypeRolePermission in _context.DocumentTypeRolePermissions on bankUserRole.RoleId equals documentTypeRolePermission.RoleId
            where bankUserRole.EndDate == null || bankUserRole.EndDate > _dateService.UtcNow 
            select new DocumentPolicyRule
            { 
                UserId = (long) bankUserRole.BankUserId,
                DocumentTypeId = documentTypeRolePermission.DocumentTypeId,
                PermissionId = documentTypeRolePermission.PermissionId,
                BranchId = bankUserRole.BranchId,
                RegionalOfficeId = bankUserRole.RegionalOfficeId,
                OfficeId = bankUserRole.OfficeId
            };
    }
}

public class DocumentAuthorizationModel : ResourceAuthorizationModel
{
    public IQueryable<DocumentPolicyRule> DocumentPolicyRules { get; }

    public DocumentAuthorizationModel(
        IQueryable<ResourcePolicyRule> resourcePolicyRules, 
        IQueryable<RolePolicyRule> rolePolicyRules, 
        IQueryable<DocumentPolicyRule> documentPolicyRules) 
        : base(resourcePolicyRules, rolePolicyRules)
    {
        DocumentPolicyRules = documentPolicyRules;
    }

    public bool HasAnyDocumentAccess(long userId)
    {
        // user, any, any - супервизор
        // user, doc, any - имеет доступ ко всем типам документов
        return ResourcePolicyRules
            .Any(r => r.UserId == userId &&
                      (r.Resource == SecurableId.Document || r.Resource == SecurableId.Any) &&
                      (r.Action == PermissionId.Any));
    }
}

public class DocumentMatcher : Matcher<DocumentAuthorizationRequest, DocumentAuthorizationModel>
{
    public DocumentMatcher(IAuthorizationModelFactory<DocumentAuthorizationModel> modelFactory) 
        : base(modelFactory)
    {
    }

    protected override IEnumerable<PolicyEffect> Match(DocumentAuthorizationRequest request, DocumentAuthorizationModel model)
    {
        if (model.IsSuperuser(request.UserId))
            yield return PolicyEffect.Allow;
        
        if (model.HasAnyDocumentAccess(request.UserId))
            yield return PolicyEffect.Allow;

        var query = model.DocumentPolicyRules
            .Where(r => r.UserId == request.UserId &&
                        r.DocumentTypeId == request.DocumentTypeId &&
                        r.PermissionId == request.PermissionId);

        query = model.ApplyOrganizationContextFilter(query, request.OrganizationContext);
        
        // проверка на доступ по типу документов
        if (query.Any())
        {
            yield return PolicyEffect.Allow;
        }
    }
}

public class DocumentAuthorizationRequest : ICurrentUserAuthorizationRequest //, IDocumentAuthorizationRequest
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
    
    public long UserId { get; set; }
    
    public DocumentTypeId DocumentTypeId { get; }

    public PermissionId PermissionId { get; }

    public OrganizationContext OrganizationContext { get; }
}