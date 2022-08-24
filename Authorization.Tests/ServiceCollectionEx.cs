using Authorization.Sample.Entities;
using LinqToDB.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Authorization.Tests;

internal static class ServiceCollectionEx
{
    public static DataContext GetInMemoryDataContext()
    {
        var connectionOptions = new LinqToDBConnectionOptionsBuilder()
            .UseSQLite("Data Source=:memory:")
            .Build();
        
        var dataContext = new DataContext(connectionOptions);
        
        dataContext.CreateTestData();
        
        return dataContext;
    }
    
    public static IServiceCollection AddInMemoryDataContext(this IServiceCollection serviceCollection)
    {
        return AddInMemoryDataContext(serviceCollection, GetInMemoryDataContext());
    }
    
    public static IServiceCollection AddInMemoryDataContext(this IServiceCollection serviceCollection, DataContext dataContext)
    {
        serviceCollection.AddSingleton(dataContext);
        
        return serviceCollection;
    }
}