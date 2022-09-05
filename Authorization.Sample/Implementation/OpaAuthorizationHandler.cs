using System.Collections;
using System.Linq.Expressions;
using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using OPADotNet.Ast;
using OPADotNet.Ast.Models;
using static Authorization.Sample.Implementation.OrgContextHelpers;

namespace Authorization.Sample.Implementation;

public class OpaAuthorizationHandler : AuthorizationHandler<OpaRequirement>
{
    private readonly IOpaClient _opaClient;
    private readonly IHttpContextAccessor _contextAccessor;

    public OpaAuthorizationHandler(IOpaClient opaClient, IHttpContextAccessor contextAccessor)
    {
        _opaClient = opaClient;
        _contextAccessor = contextAccessor;
    }

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, OpaRequirement requirement)
    {
        if (context.Resource is QueryableWrapper wrapper)
        {
            await HandleQueryRequirementAsync(context, requirement, wrapper);
        }
        else
        {
            await HandleResourceRequirementAsync(context, requirement);
        }
    }

    private async Task HandleQueryRequirementAsync(AuthorizationHandlerContext context, OpaRequirement requirement, QueryableWrapper wrapper)
    {
        var query = requirement.GetQuery();
        var subject = OpaInputUser.FromPrincipal(context.User);
        var unknown = "input.Resource";
        var (branchId, regionalOfficeId, officeId) = GetOrganizationContext();
        var input = new OpaInput
        {
            Subject = subject,
            PermissionId = requirement.PermissionId,
            SecurableId = requirement.SecurableId,
            Extensions = new Dictionary<string, object>
            {
                [nameof(OrganizationContext)] = new
                {
                    BranchId = ToOrgContextValue(branchId),
                    RegionalOfficeId = ToOrgContextValue(regionalOfficeId),
                    OfficeId = ToOrgContextValue(officeId),
                }
            }
        };
       
        var result = await _opaClient.Compile(query, input, new[] { unknown });
        if (result.Result.Queries != null)
        {
            Expression expression = Expression.Constant(false);
        
            var visitor = new ExpressionVisitor(wrapper.Type);
            foreach (var body in result.Result.Queries)
            {
                visitor.Visit(body);
            
                if (visitor.ResultExpression != null)
                    expression = Expression.Or(visitor.ResultExpression, expression);
            }

            wrapper.Expression = Expression.Lambda(expression, visitor.ParameterExpression);
        
            context.Succeed(requirement);
        }
    }
    
    private async Task HandleResourceRequirementAsync(AuthorizationHandlerContext context, OpaRequirement requirement)
    {
        var policy = requirement.GetPolicy();
        var subject = OpaInputUser.FromPrincipal(context.User);
        var (branchId, regionalOfficeId, officeId) = GetOrganizationContext();
        var input = new OpaInput
        {
            Subject = subject,
            PermissionId = requirement.PermissionId,
            SecurableId = requirement.SecurableId,
            Extensions = new Dictionary<string, object>
            {
                [nameof(OrganizationContext)] = new
                {
                    BranchId = ToOrgContextValue(branchId),
                    RegionalOfficeId = ToOrgContextValue(regionalOfficeId),
                    OfficeId = ToOrgContextValue(officeId),
                }
            }
        };

        if (context.Resource != null && context.Resource is not HttpContext)
        {
            input.Extensions["Resource"] = context.Resource;
        }
        
        var result = await _opaClient.Evaluate(policy, input);
        if (result)
        {
            context.Succeed(requirement);
        }
    }

    private (long?, long?, long?) GetOrganizationContext()
    {
        var query = _contextAccessor.HttpContext?.Request.Query;
        if (query != null)
        {
            if (query.TryGetValue("branchId", out var branchIdString) && 
                long.TryParse(branchIdString, out var branchId))
            {
                long? regionalOfficeId = 
                    query.TryGetValue("regionalOfficeId", out var regionalOfficeIdString) && long.TryParse(regionalOfficeIdString, out var regionalOfficeIdValue)
                        ? regionalOfficeIdValue
                        : null;

                long? officeId = 
                    query.TryGetValue("regionalOfficeId", out var officeIdString) && long.TryParse(officeIdString, out var officeIdValue)
                        ? officeIdValue
                        : null;

                return (branchId, regionalOfficeId, officeId);
            }
        }

        return (null, null, null);
    }
}

internal class QueryableWrapper
{
    public QueryableWrapper(Type type)
    {
        Type = type;
    }
    
    public Type Type { get; }
    
    public Expression Expression { get; set; }
}

internal class ExpressionVisitor : AstVisitor<Expression>
{
    public ExpressionVisitor(Type type)
    {
        Type = type;
        ParameterExpression = Expression.Parameter(type, "_");
        ResultExpression = null;
    }

    public Type Type { get; }
   
    public ParameterExpression ParameterExpression { get; }
    
    public Expression ResultExpression { get; private set; }
    
    public override Expression VisitExpression(AstExpression partialExpression)
    {
        string propertyName = null;
        foreach (var term in partialExpression.Terms)
        {
            if (term is AstTermRef astRef)
            {
                // property access
                if (astRef.Value.Count >= 3 &&
                    astRef.Value[0] is AstTermVar { Value: "input" } &&
                    astRef.Value[1] is AstTermString { Value: "Resource" } &&
                    astRef.Value[2] is AstTermString termString)
                {
                    propertyName = termString.Value;
                }
            }

            if (propertyName != null)
            {
                if (term is AstTermSet astSet)
                {
                    var property = Type.GetProperty(propertyName);
                    if (property == null) 
                        throw new InvalidOperationException($"Property '{propertyName}' missing");
                    
                    var listType = typeof(List<>).MakeGenericType(property.PropertyType);
                    var list = (IList) Activator.CreateInstance(listType, astSet.Value.Count)!;
                    
                    foreach (var astTerm in astSet.Value)
                    {
                        if (astTerm is not AstTermString astString) 
                            continue;
                        
                        if (property.PropertyType.IsEnum)
                        {
                            var enumValue = Enum.Parse(property.PropertyType, astString.Value);

                            list.Add(enumValue);
                        }
                        else
                        {
                            list.Add(astString.Value);
                        }
                    }

                    var memberExpression = GetMemberExpression(ParameterExpression, propertyName);
                    var inExpression = GetInExpression(memberExpression, Expression.Constant(list));

                    ResultExpression = ResultExpression != null 
                        ? Expression.AndAlso(ResultExpression, inExpression) 
                        : inExpression;
                }
            }
        }
        
        return base.VisitExpression(partialExpression);
    }

    private static MemberExpression GetMemberExpression(ParameterExpression param, string propertyName)
    {
        return GetMemberExpression((Expression)param, propertyName);
    }

    private static MemberExpression GetMemberExpression(Expression param, string propertyName)
    {
        if (!propertyName.Contains("."))
            return Expression.PropertyOrField(param, propertyName);

        var index = propertyName.IndexOf(".", StringComparison.Ordinal);
        var subParam = Expression.PropertyOrField(param, propertyName.Substring(0, index));
        return GetMemberExpression(subParam, propertyName.Substring(index + 1));
    }

    private Expression GetInExpression(MemberExpression member, ConstantExpression constant1)
    {
        if (!(constant1.Value is IList) || !constant1.Value.GetType().IsGenericType)
            throw new ArgumentException("The 'Contains' operation only supports lists as parameters.");
            
        var type = constant1.Value.GetType();
        var inInfo = typeof(Enumerable)
            .GetMethods()
            .Single(mi => mi.Name == "Contains" && mi.GetParameters().Length == 2)
            .MakeGenericMethod(type.GenericTypeArguments[0]);

        return GetInExpressionHandlingNullables(member, constant1, type, inInfo) ?? Expression.Call(null, inInfo, constant1, member);
    }

    private Expression GetInExpressionHandlingNullables(MemberExpression member, ConstantExpression constant1, Type type,
        MethodInfo inInfo)
    {
        var listUnderlyingType = Nullable.GetUnderlyingType(type.GetGenericArguments()[0]);
        var memberUnderlingType = Nullable.GetUnderlyingType(member.Type);
        if (listUnderlyingType != null && memberUnderlingType == null)
        {
            return Expression.Call(null, inInfo, constant1, member.Expression);
        }

        return null;
    }
}