using Authorization.Permissions;
using Authorization.Sample.Entities;
using Authorization.Sample.Services;
using LinqToDB;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using DataContext = Authorization.Sample.Entities.DataContext;

namespace Authorization.Sample.Controllers;

[ApiController]
[Route("[controller]")]
public class DocumentController : ControllerBase
{
    private readonly DataContext _context;
    private readonly IAuthorizationEnforcer _authorizationEnforcer;

    public DocumentController(DataContext context, IAuthorizationEnforcer authorizationEnforcer)
    {
        _context = context;
        _authorizationEnforcer = authorizationEnforcer;
    }

    [HttpGet]
    [Authorize(Securables.DocumentView)]
    public async Task<IEnumerable<Document>> Get()
    {
        var query = await _authorizationEnforcer
            .EnforceQueryable(_context.Documents);
        
        return query.ToArray();
    }

    [HttpGet("{id}")]
    [Authorize(Securables.DocumentView)]
    public async Task<Document> Get(long id)
    {
        var query = await _authorizationEnforcer
            .EnforceQueryable(_context.Documents);
        
        return query.SingleOrDefault(d => d.Id == id);
    }
    
    [HttpPut]
    [Authorize(Securables.DocumentManage)]
    public async Task<long> Put(Document document)
    {
        if (await _authorizationEnforcer.Enforce(document))
        {
            return await _context.Documents.InsertWithInt64IdentityAsync(() => new Document
            {
                DocumentTypeId = document.DocumentTypeId,
                BranchId = document.BranchId,
                OfficeId = document.OfficeId
            });
        }

        return -1;
    }
    
    [HttpPost]
    [Authorize(Securables.DocumentManage)]
    public async Task Post(Document document)
    {
        if (await _authorizationEnforcer.Enforce(document))
        {
            await _context.Documents
                .Where(d => d.Id == document.Id)
                .Set(d => d.DocumentTypeId, document.DocumentTypeId)
                .Set(d => d.BranchId, document.BranchId)
                .Set(d => d.OfficeId, document.OfficeId)
                .UpdateAsync();
        }
    }
    
    [HttpDelete]
    [Authorize(Securables.DocumentManage)]
    public async Task Delete(long id)
    {
        var document = _context.Documents.SingleOrDefault(d => d.Id == id);
        if (document == null) return;

        if (await _authorizationEnforcer.Enforce(document))
        {
            await _context.Documents
                .Where(d => d.Id == document.Id)
                .DeleteAsync();
        }
    }
}