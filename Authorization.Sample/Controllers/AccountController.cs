using Authorization.Permissions;
using Authorization.Sample.Entities;
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
    private readonly IAuthorizationService _authorizationService;
    
    public AccountController(DataContext context, IAuthorizationService authorizationService)
    {
        _context = context;
        _authorizationService = authorizationService;
    }

    [HttpGet("{id}")]
    [Authorize(Securables.AccountView)]
    public async Task<Account> Get(long id)
    {
        var account = _context.Accounts.SingleOrDefault(a => a.Id == id);
        if (account == null) return null;

        var result = await _authorizationService.AuthorizeAsync(User, account, Securables.AccountView);
        if (result.Succeeded)
            return account;

        return null;
    }

    [HttpPut]
    [Authorize(Securables.AccountCreate)]
    public async Task<long> Put([FromQuery] string accountNumber)
    {
        if (TryGetGL2(accountNumber, out var gl2))
        {
            var result = await _authorizationService.AuthorizeAsync(User, new Account { GL2 = gl2 }, Securables.AccountView);
            if (result.Succeeded)
            {
                return await _context.Accounts
                    .InsertWithInt64IdentityAsync(() => new Account { Number = accountNumber, GL2 = gl2 });
            }
        }

        return -1;
    }
    
    [HttpPost("{id}")]
    [Authorize(Securables.AccountChange)]
    public async Task Post(long id, [FromQuery] string accountNumber)
    {
        if (TryGetGL2(accountNumber, out var gl2))
        {
            var result = await _authorizationService.AuthorizeAsync(User, new Account { GL2 = gl2 }, Securables.AccountView);
            if (result.Succeeded)
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
    [Authorize(Securables.AccountDelete)]
    public async Task Delete(long id)
    {
        var account = _context.Accounts.SingleOrDefault(a => a.Id == id);
        if (account == null) return;

        var result = await _authorizationService.AuthorizeAsync(User, account, Securables.AccountView);
        if (result.Succeeded)
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