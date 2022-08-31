using Authorization.Sample.Entities;
using Authorization.Sample.Implementation;
using Authorization.Sample.Services;
using Microsoft.AspNetCore.Mvc;
using LinqToDB;
using DataContext = Authorization.Sample.Entities.DataContext;

namespace Authorization.Sample.Controllers;

[ApiController]
[Route("[controller]")]
public class DocumentationFileCategoryController : ControllerBase
{
    private readonly DataContext _context;
    private readonly AuthorizationEnforcer _enforcer;

    public DocumentationFileCategoryController(DataContext context, AuthorizationEnforcer enforcer)
    {
        _context = context;
        _enforcer = enforcer;
    }
    
    [HttpGet]
    [SecurablePermission(SecurableId.DocumentationFile, PermissionId.View)]
    public IEnumerable<DocumentationFileCategory> Get()
    {
        var query = _enforcer
            .EnforceFilter(_context.DocumentationFileCategories);
        
        return query.ToArray();
    }

    [HttpGet("{id}")]
    [SecurablePermission(SecurableId.DocumentationFile, PermissionId.View)]
    public DocumentationFileCategory Get(long id)
    {
        var query = _enforcer
            .EnforceFilter(_context.DocumentationFileCategories);
        
        return query.SingleOrDefault(d => d.Id == id);
    }
    
    [HttpPut]
    [SecurablePermission(SecurableId.DocumentationFile, PermissionId.Create)]
    public long Put(DocumentationFileCategory category)
    {
        return _context.DocumentationFileCategories
            .InsertWithInt64Identity(() => new DocumentationFileCategory
            {
                CategoryType = category.CategoryType,
                Name = category.Name
            });
    }
    
    [HttpPost]
    [SecurablePermission(SecurableId.DocumentationFile, PermissionId.Change)]
    public void Post(DocumentationFileCategory category)
    {
        _context.DocumentationFileCategories
            .Where(d => d.Id == category.Id)
            .Set(d => d.CategoryType, category.CategoryType)
            .Set(d => d.Name, category.Name)
            .Update();
    }
    
    [HttpDelete]
    [SecurablePermission(SecurableId.DocumentationFile, PermissionId.Delete)]
    public void Delete(long id)
    {
        var document = _context.DocumentationFileCategories.SingleOrDefault(d => d.Id == id);
        if (document == null) return;

        _context.DocumentationFileCategories
            .Where(d => d.Id == document.Id)
            .Delete();
    }
}