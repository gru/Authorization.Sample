namespace Authorization.Sample.Implementation;

public class DocumentMatcher : Matcher<DocumentAuthorizationRequest, DocumentAuthorizationModel>
{
    public DocumentMatcher(IAuthorizationModelFactory<DocumentAuthorizationModel> modelFactory) 
        : base(modelFactory)
    {
    }

    protected override IEnumerable<PolicyEffect> Match(DocumentAuthorizationRequest request, DocumentAuthorizationModel model)
    {
        if (model.HasAnyDocumentAccess(request.UserId))
            yield return PolicyEffect.Allow;

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
    }
}