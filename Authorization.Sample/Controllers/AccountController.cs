using Authorization.Sample.Entities;
using Authorization.Sample.Implementation;
using Authorization.Sample.Services;
using Microsoft.AspNetCore.Mvc;
using LinqToDB;
using DataContext = Authorization.Sample.Entities.DataContext;

namespace Authorization.Sample.Controllers;

[ApiController]
[Route("[controller]")]
public class AccountController : ControllerBase
{
    private readonly DataContext _context;
    private readonly AuthorizationEnforcer _enforcer;
    
    public AccountController(DataContext context, AuthorizationEnforcer enforcer)
    {
        _context = context;
        _enforcer = enforcer;
    }

    [HttpGet("{id}")]
    [ResourcePermission(SecurableId.Account, PermissionId.View)]
    public Account Get(long id)
    {
        var account = _context.Accounts.SingleOrDefault(a => a.Id == id);
        if (account == null) return null;

        if (_enforcer.Enforce(new AccountAuthorizationRequest(account, PermissionId.View)))
            return account;

        return null;
    }

    [HttpPut]
    [ResourcePermission(SecurableId.Account, PermissionId.Create)]
    public long Put([FromQuery] string accountNumber)
    {
        if (TryGetGL2(accountNumber, out var gl2))
        {
            if (_enforcer.Enforce(new AccountAuthorizationRequest(gl2, PermissionId.Create)))
            {
                return _context.Accounts
                    .InsertWithInt64Identity(() => new Account { Number = accountNumber, GL2 = gl2 });
            }
        }

        return -1;
    }
    
    [HttpPost("{id}")]
    [ResourcePermission(SecurableId.Account, PermissionId.Change)]
    public void Post(long id, [FromQuery] string accountNumber)
    {
        if (TryGetGL2(accountNumber, out var gl2))
        {
            if (_enforcer.Enforce(new AccountAuthorizationRequest(gl2, PermissionId.Create)))
            {
                _context.Accounts
                    .Where(a => a.Id == id)
                    .Set(a => a.Number, accountNumber)
                    .Set(a => a.GL2, gl2)
                    .Update();
            }
        }
    }

    [HttpDelete("{id}")]
    [ResourcePermission(SecurableId.Account, PermissionId.Change)]
    public void Delete(long id)
    {
        var account = _context.Accounts.SingleOrDefault(a => a.Id == id);
        if (account == null) return;

        if (_enforcer.Enforce(new AccountAuthorizationRequest(account, PermissionId.Delete)))
        {
            _context.Accounts
                .Where(a => a.Id == id)
                .Delete();
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