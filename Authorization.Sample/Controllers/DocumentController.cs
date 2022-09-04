using Authorization.Permissions;
using Authorization.Sample.Entities;
using Authorization.Sample.Implementation;
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
    private readonly IAuthorizationService _authorizationService;

    public DocumentController(DataContext context, IAuthorizationService authorizationService)
    {
        _context = context;
        _authorizationService = authorizationService;
    }

    [HttpGet]
    [Authorize(Securables.DocumentView)]
    public IEnumerable<Document> Get()
    {
        var query = _authorizationService
            .AuthorizeQueryable(_context.Documents);
        
        return query.ToArray();
    }

    [HttpGet("{id}")]
    [Authorize(Securables.DocumentView)]
    public Document Get(long id)
    {
        var query = _authorizationService
            .AuthorizeQueryable(_context.Documents);
        
        return query.SingleOrDefault(d => d.Id == id);
    }
    
    [HttpPut]
    [Authorize(Securables.DocumentCreate)]
    public async Task<long> Put(Document document)
    {
        var result = await _authorizationService.AuthorizeAsync(User, document, Securables.DocumentCreate);
        if (result.Succeeded)
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
    [Authorize(Securables.DocumentChange)]
    public async Task Post(Document document)
    {
        var result = await _authorizationService.AuthorizeAsync(User, document, Securables.DocumentChange);
        if (result.Succeeded)
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
    [Authorize(Securables.DocumentDelete)]
    public async Task Delete(long id)
    {
        var document = _context.Documents.SingleOrDefault(d => d.Id == id);
        if (document == null) return;

        var result = await _authorizationService.AuthorizeAsync(User, document, Securables.DocumentChange);
        if (result.Succeeded)
        {
            await _context.Documents
                .Where(d => d.Id == document.Id)
                .DeleteAsync();
        }
    }
}