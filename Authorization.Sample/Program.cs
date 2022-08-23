using Microsoft.Extensions.DependencyInjection;

namespace Authorization.Sample;

public static class Program
{
    public static void Main(string[] args)
    {
        Console.WriteLine("Hello, World!");
    }
}

public enum SecurableId
{
    Document = 1, DocumentationFile = 2, Any = 3
}

public enum PermissionId
{
    View = 1, Create = 2, Change = 3, Delete = 4, Any = 5
}

public static class Securables
{
    public static readonly SecurableId Document = SecurableId.Document;
    public static readonly SecurableId DocumentationFile = SecurableId.DocumentationFile;
}

public static class Permissions
{
    public static readonly PermissionId View = PermissionId.View;
    public static readonly PermissionId Create = PermissionId.Create;
    public static readonly PermissionId Change = PermissionId.Change;
    public static readonly PermissionId Delete = PermissionId.Delete;
}

public class OrganizationContext
{
    public OrganizationContext(long branchId)
    {
        BranchId = branchId;
    }

    public OrganizationContext(long branchId, long regionalOfficeId)
        : this(branchId)
    {
        RegionalOfficeId = regionalOfficeId;
    }

    public OrganizationContext(long branchId, long? regionalOfficeId, long officeId)
    {
        BranchId = branchId;
        RegionalOfficeId = regionalOfficeId;
        OfficeId = officeId;
    }

    public long BranchId { get; }
    
    public long? RegionalOfficeId { get; }
    
    public long? OfficeId { get; }
}

public interface ICurrentUserAuthorizationRequest
{
    public long UserId { get; set; }
}

public interface IOrganizationContextRule
{
    long? BranchId { get; }
    
    long? RegionalOfficeId { get; }
    
    long? OfficeId { get; }
}

public class ResourceAuthorizationRequest : ICurrentUserAuthorizationRequest
{
    public ResourceAuthorizationRequest(SecurableId resource, PermissionId action, OrganizationContext organizationContext = null)
    {
        Resource = resource;
        Action = action;
        OrganizationContext = organizationContext;
    }

    public long UserId { get; set; }
    
    public SecurableId Resource { get; }
    
    public PermissionId Action { get; }

    public OrganizationContext OrganizationContext { get; }
}

public class ResourceAuthorizationModel
{
    public ResourceAuthorizationModel(
        IQueryable<ResourcePolicyRule> resourcePolicyRules, 
        IQueryable<RolePolicyRule> rolePolicyRules)
    {
        ResourcePolicyRules = resourcePolicyRules;
        RolePolicyRules = rolePolicyRules;
    }

    public IQueryable<ResourcePolicyRule> ResourcePolicyRules { get; }

    public IQueryable<RolePolicyRule> RolePolicyRules { get; }

    public bool IsSuperuser(long userId)
    {
        return RolePolicyRules.Any(r => r.UserId == userId && r.RoleName == "Superuser");
    }

    public bool HasPermission(long userId, SecurableId securableId, PermissionId permissionId, OrganizationContext ctx)
    {
        var query = ResourcePolicyRules
            .Where(r => r.UserId == userId && 
                        (r.Resource == securableId || r.Resource == SecurableId.Any) &&
                        (r.Action == permissionId || r.Action == PermissionId.Any));

        query = ApplyOrganizationContextFilter(query, ctx);

        return query.Any();
    }

    public IQueryable<T> ApplyOrganizationContextFilter<T>(IQueryable<T> query, OrganizationContext ctx)
        where T : IOrganizationContextRule
    {
        if (ctx == null)
        {
            query = query
                .Where(r => r.BranchId == null && r.RegionalOfficeId == null && r.OfficeId == null);
        }
        else
        {
            query = query
                .Where(r => (r.BranchId == null && r.RegionalOfficeId == null && r.OfficeId == null) ||
                            (r.BranchId == ctx.BranchId && 
                             (r.RegionalOfficeId == null || 
                              (ctx.RegionalOfficeId == null && ctx.OfficeId != null) || 
                              (r.RegionalOfficeId == ctx.RegionalOfficeId)) && 
                             (r.OfficeId == null || r.OfficeId == ctx.OfficeId)));
        }

        return query;
    }
}

public class ResourcePolicyRule : IOrganizationContextRule
{
    public long UserId { get; set; }
    
    public SecurableId Resource { get; set; }
    
    public PermissionId Action { get; set; }

    public long? BranchId { get; set; }
    
    public long? RegionalOfficeId { get; set; }
    
    public long? OfficeId { get; set; }
}

public class RolePolicyRule
{
    public long UserId { get; set; }

    public string RoleName { get; set; }
}

public enum PolicyEffect
{
    Allow, Deny
}

public interface IAuthorizationModelFactory<out TModel>
{
    public TModel PrepareModel();
}

public interface IMatcher<in TRequest>
{
    IEnumerable<PolicyEffect> Match(TRequest request);
}

public abstract class Matcher<TRequest, TModel> : IMatcher<TRequest>
{
    private readonly IAuthorizationModelFactory<TModel> _modelFactory;

    protected Matcher(IAuthorizationModelFactory<TModel> modelFactory)
    {
        _modelFactory = modelFactory;
    }

    public IEnumerable<PolicyEffect> Match(TRequest request)
    {
        return Match(request, _modelFactory.PrepareModel());
    }

    protected abstract IEnumerable<PolicyEffect> Match(TRequest request, TModel model);
}

public class ResourcePermissionMatcher : Matcher<ResourceAuthorizationRequest, ResourceAuthorizationModel>
{
    public ResourcePermissionMatcher(IAuthorizationModelFactory<ResourceAuthorizationModel> modelFactory) 
        : base(modelFactory)
    {
    }

    protected override IEnumerable<PolicyEffect> Match(ResourceAuthorizationRequest request, ResourceAuthorizationModel model)
    {
        if (model.IsSuperuser(request.UserId))
            yield return PolicyEffect.Allow;

        if (model.HasPermission(request.UserId, request.Resource, request.Action, request.OrganizationContext))
            yield return PolicyEffect.Allow;
    }
}

public class Enforcer
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ICurrentUserService _currentUserService;

    public Enforcer(IServiceProvider serviceProvider, ICurrentUserService currentUserService)
    {
        _serviceProvider = serviceProvider;
        _currentUserService = currentUserService;
    }

    public bool Enforce<TRequest>(TRequest request)
    {
        if (request is ICurrentUserAuthorizationRequest currentUserAuthorizationRequest)
            currentUserAuthorizationRequest.UserId = _currentUserService.UserId;

        var matcher = _serviceProvider.GetService<IMatcher<TRequest>>()!;
        
        var effects = matcher.Match(request);
        
        return effects.Any(e => e == PolicyEffect.Allow);
    }

    public IQueryable<T> EnforceFilter<T, TRequest>(IQueryable<T> query, TRequest request)
    {
        if (request is ICurrentUserAuthorizationRequest currentUserAuthorizationRequest)
            currentUserAuthorizationRequest.UserId = _currentUserService.UserId;

        var filter = _serviceProvider.GetService<IFilter<T, TRequest>>()!;

        return filter.Apply(query, request);
    }
}

public interface IFilter<T, in TContext>
{
    IQueryable<T> Apply(IQueryable<T> query, TContext request);
}

public abstract class Filter<T, TContext, TModel> : IFilter<T, TContext>
{
    private readonly IAuthorizationModelFactory<TModel> _modelFactory;

    protected Filter(IAuthorizationModelFactory<TModel> modelFactory)
    {
        _modelFactory = modelFactory;
    }

    public IQueryable<T> Apply(IQueryable<T> query, TContext request)
    {
        return Apply(query, request, _modelFactory.PrepareModel());
    }

    protected abstract IQueryable<T> Apply(IQueryable<T> query, TContext request, TModel model);
}