using Authorization.Permissions;
using Authorization.Sample.Entities;
using Authorization.Sample.Implementation;
using Authorization.Sample.Services;
using Microsoft.AspNetCore.Mvc;
using LinqToDB;
using Microsoft.AspNetCore.Authorization;
using DataContext = Authorization.Sample.Entities.DataContext;

namespace Authorization.Sample.Controllers;

[ApiController]
[Route("[controller]")]
public class DocumentationFileCategoryController : ControllerBase
{
    private readonly DataContext _context;
    private readonly IAuthorizationService _authorizationService;

    public DocumentationFileCategoryController(DataContext context, IAuthorizationService authorizationService)
    {
        _context = context;
        _authorizationService = authorizationService;
    }
    
    [HttpGet]
    [Authorize(Securables.DocumentationFileView)]
    public IEnumerable<DocumentationFileCategory> Get()
    {
        var query = _authorizationService
            .AuthorizeQueryable(_context.DocumentationFileCategories);
        
        return query.ToArray();
    }

    [HttpGet("{id}")]
    [Authorize(Securables.DocumentationFileView)]
    public DocumentationFileCategory Get(long id)
    {
        var query = _authorizationService
            .AuthorizeQueryable(_context.DocumentationFileCategories);
        
        return query.SingleOrDefault(d => d.Id == id);
    }
    
    [HttpPut]
    [Authorize(Securables.DocumentationFileCreate)]
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
    [Authorize(Securables.DocumentationFileChange)]
    public void Post(DocumentationFileCategory category)
    {
        _context.DocumentationFileCategories
            .Where(d => d.Id == category.Id)
            .Set(d => d.CategoryType, category.CategoryType)
            .Set(d => d.Name, category.Name)
            .Update();
    }
    
    [HttpDelete("{id}")]
    [Authorize(Securables.DocumentationFileDelete)]
    public void Delete(long id)
    {
        var document = _context.DocumentationFileCategories.SingleOrDefault(d => d.Id == id);
        if (document == null) return;

        _context.DocumentationFileCategories
            .Where(d => d.Id == document.Id)
            .Delete();
    }
}