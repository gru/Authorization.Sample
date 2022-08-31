using System;
using Authorization.Sample.Entities;
using Authorization.Sample.Implementation;
using Authorization.Sample.Services;
using Casbin;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Authorization.Tests;

public class AccountEnforcerTests
{
    [Fact]
    public void Enforce_BankUser_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.BankUser);
        
        Assert.True(enforcer.Enforce(new AccountAuthorizationRequest("30101", PermissionId.View)));
        Assert.False(enforcer.Enforce(new AccountAuthorizationRequest("30101", PermissionId.Change)));
        Assert.False(enforcer.Enforce(new AccountAuthorizationRequest("30102", PermissionId.View)));
        Assert.False(enforcer.Enforce(new AccountAuthorizationRequest("30102", PermissionId.Change)));
    }
    
    [Fact]
    public void Enforce_Supervisor_Permissions()
    {
        var enforcer = CreateEnforcer(BankUserId.Supervisor);
        
        Assert.True(enforcer.Enforce(new AccountAuthorizationRequest("30101", PermissionId.View)));
        Assert.True(enforcer.Enforce(new AccountAuthorizationRequest("30101", PermissionId.Change)));
        Assert.True(enforcer.Enforce(new AccountAuthorizationRequest("30102", PermissionId.View)));
        Assert.True(enforcer.Enforce(new AccountAuthorizationRequest("30102", PermissionId.Change)));
    }
    
    private static AuthorizationEnforcer CreateEnforcer(BankUserId currentUser, bool demo = false)
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddInMemoryDataContext();
        serviceCollection.AddSingleton<ICurrentUserService>(new TestCurrentUserService(currentUser));
        serviceCollection.AddSingleton<IDemoService>(new DemoService(demo));
        serviceCollection.AddSingleton<ICurrentDateService>(new TestCurrentDateService(DateTimeOffset.Now));
        serviceCollection.AddSingleton<IAuthorizationModelFactory<IEnforcer>, CasbinAuthorizationModelFactory>();
        serviceCollection.AddSingleton<IMatcher<ResourceAuthorizationRequest>, ResourceCasbinMatcher>();
        serviceCollection.AddSingleton<IMatcher<AccountAuthorizationRequest>, AccountCasbinMatcher>();
        serviceCollection.AddSingleton<AuthorizationEnforcer>();

        return serviceCollection.BuildServiceProvider().GetService<AuthorizationEnforcer>();
    }
}