using Authorization.Sample.Entities;
using Authorization.Sample.Implementation;
using Authorization.Sample.Services;
using Microsoft.AspNetCore.Mvc;

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
    [ResourcePermission(SecurableId.Document, PermissionId.Create)]
    public void Put(Document document)
    {
        if (_enforcer.Enforce(new DocumentAuthorizationRequest(document.DocumentTypeId, PermissionId.Create)))
        {
        }
    }
    
    [HttpPost]
    [ResourcePermission(SecurableId.Document, PermissionId.Change)]
    public void Post(Document document)
    {
        if (_enforcer.Enforce(new DocumentAuthorizationRequest(document.DocumentTypeId, PermissionId.Change)))
        {
        }
    }
    
    [HttpDelete]
    [ResourcePermission(SecurableId.Document, PermissionId.Delete)]
    public void Delete(long id)
    {
        var document = _context.Documents.SingleOrDefault(d => d.Id == id);
        if (document == null) return;

        if (_enforcer.Enforce(new DocumentAuthorizationRequest(document, PermissionId.Delete)))
        {
        }
    }
}