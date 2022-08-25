using Authorization.Sample.Entities;
using Authorization.Sample.Implementation;
using Authorization.Sample.Services;
using LinqToDB;
using Microsoft.AspNetCore.Mvc;
using DataContext = Authorization.Sample.Entities.DataContext;

namespace Authorization.Sample.Controllers;

[ApiController]
[Route("[controller]")]
public class DocumentController : ControllerBase
{
    private readonly DataContext _context;
    private readonly AuthorizationEnforcer _enforcer;

    public DocumentController(DataContext context, AuthorizationEnforcer enforcer)
    {
        _context = context;
        _enforcer = enforcer;
    }

    [HttpGet]
    [ResourcePermission(SecurableId.Document, PermissionId.View)]
    public IEnumerable<Document> Get()
    {
        var query = _enforcer
            .EnforceFilter(_context.Documents, new DocumentFilterRequest());
        
        return query.ToArray();
    }

    [HttpGet("{id}")]
    [ResourcePermission(SecurableId.Document, PermissionId.View)]
    public Document Get(long id)
    {
        var query = _enforcer
            .EnforceFilter(_context.Documents, new DocumentFilterRequest());
        
        return query.SingleOrDefault(d => d.Id == id);
    }
    
    [HttpPut]
    public long Put(Document document)
    {
        if (_enforcer.Enforce(new DocumentAuthorizationRequest(document.DocumentTypeId, PermissionId.Create)))
        {
            return _context.Documents.InsertWithInt64Identity(() => new Document
            {
                DocumentTypeId = document.DocumentTypeId,
                BranchId = document.BranchId,
                OfficeId = document.OfficeId
            });
        }

        return -1;
    }
    
    [HttpPost]
    public void Post(Document document)
    {
        if (_enforcer.Enforce(new DocumentAuthorizationRequest(document.DocumentTypeId, PermissionId.Change)))
        {
            _context.Documents
                .Where(d => d.Id == document.Id)
                .Set(d => d.DocumentTypeId, document.DocumentTypeId)
                .Set(d => d.BranchId, document.BranchId)
                .Set(d => d.OfficeId, document.OfficeId)
                .Update();
        }
    }
    
    [HttpDelete]
    public void Delete(long id)
    {
        var document = _context.Documents.SingleOrDefault(d => d.Id == id);
        if (document == null) return;

        if (_enforcer.Enforce(new DocumentAuthorizationRequest(document, PermissionId.Delete)))
        {
            _context.Documents
                .Where(d => d.Id == document.Id)
                .Delete();
        }
    }
}