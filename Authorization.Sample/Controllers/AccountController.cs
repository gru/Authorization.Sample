using Authorization.Permissions;
using Authorization.Sample.Entities;
using Authorization.Sample.Services;
using Microsoft.AspNetCore.Mvc;
using LinqToDB;
using Microsoft.AspNetCore.Authorization;
using DataContext = Authorization.Sample.Entities.DataContext;

namespace Authorization.Sample.Controllers;

[ApiController]
[Route("[controller]")]
public class AccountController : ControllerBase
{
    private readonly DataContext _context;
    private readonly IAuthorizationEnforcer _authorizationEnforcer;
    
    public AccountController(DataContext context, IAuthorizationEnforcer authorizationEnforcer)
    {
        _context = context;
        _authorizationEnforcer = authorizationEnforcer;
    }

    [HttpGet("{id}")]
    [Authorize(Securables.AccountView)]
    public async Task<Account> Get(long id)
    {
        var account = _context.Accounts.SingleOrDefault(a => a.Id == id);
        if (account == null) return null;

        if (await _authorizationEnforcer.Enforce(account))
            return account;

        return null;
    }

    [HttpPut]
    [Authorize(Securables.AccountManage)]
    public async Task<long> Put([FromQuery] string accountNumber)
    {
        if (TryGetGL2(accountNumber, out var gl2))
        {
            if (await _authorizationEnforcer.Enforce(new Account { Number = accountNumber, GL2 = gl2 }))
            {
                return await _context.Accounts
                    .InsertWithInt64IdentityAsync(() => new Account { Number = accountNumber, GL2 = gl2 });
            }
        }

        return -1;
    }
    
    [HttpPost("{id}")]
    [Authorize(Securables.AccountManage)]
    public async Task Post(long id, [FromQuery] string accountNumber)
    {
        if (TryGetGL2(accountNumber, out var gl2))
        {
            if (await _authorizationEnforcer.Enforce(new Account { Number = accountNumber, GL2 = gl2 }))
            {
                await _context.Accounts
                    .Where(a => a.Id == id)
                    .Set(a => a.Number, accountNumber)
                    .Set(a => a.GL2, gl2)
                    .UpdateAsync();
            }
        }
    }

    [HttpDelete("{id}")]
    [Authorize(Securables.AccountManage)]
    public async Task Delete(long id)
    {
        var account = _context.Accounts.SingleOrDefault(a => a.Id == id);
        if (account == null) return;

        if (await _authorizationEnforcer.Enforce(account))
        {
            await _context.Accounts
                .Where(a => a.Id == id)
                .DeleteAsync();
        }
    }
    
    private static bool TryGetGL2(string accountNumber, out string gl2)
    {
        gl2 = accountNumber.Length == 20 
            ? accountNumber.Substring(0, 5)
            : null;

        return gl2 != null;
    }
}