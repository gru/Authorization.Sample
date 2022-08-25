using Authorization.Sample.Entities;
using Authorization.Sample.Services;

namespace Authorization.Sample.Implementation;

public class DocumentMatcher : Matcher<DocumentAuthorizationRequest, DocumentAuthorizationModel>
{
    private readonly IDemoService _demoService;

    public DocumentMatcher(IAuthorizationModelFactory<DocumentAuthorizationModel> modelFactory, IDemoService demoService) 
        : base(modelFactory)
    {
        _demoService = demoService;
    }

    protected override IEnumerable<PolicyEffect> Match(DocumentAuthorizationRequest request, DocumentAuthorizationModel model)
    {
        if (_demoService.IsDemoModeActive && !model.IsReadOnlyPermission(request.PermissionId))
        {
            yield return PolicyEffect.Deny;
        }
        else if (model.IsSuperuser(request.UserId))
        {
            yield return PolicyEffect.Allow;
        }
        else
        {
            var query = model.DocumentPolicyRules
                .Where(r => r.UserId == request.UserId &&
                            r.DocumentTypeId == request.DocumentTypeId &&
                            r.PermissionId == request.PermissionId);

            query = model.ApplyOrganizationContextFilter(query, request.OrganizationContext);
        
            // проверка на доступ по типу документов
            if (query.Any())
            {
                yield return PolicyEffect.Allow;
            }
            else
            {
                if (model.HasPermission(request.UserId, SecurableId.Document, request.PermissionId, request.OrganizationContext))
                    yield return PolicyEffect.Allow;
            }
        }
    }
}