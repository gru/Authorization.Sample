using System.Linq.Expressions;

namespace Authorization.Sample.Implementation;

internal class QueryableWrapper
{
    public QueryableWrapper(Type type)
    {
        Type = type;
    }
    
    public Type Type { get; }
    
    public Expression Expression { get; set; }
}