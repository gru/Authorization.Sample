namespace Authorization.Permissions;

public static class Securables
{
    public const string DocumentationFileView = "DocumentationFile.View";
    public const string DocumentationFileCreate = "DocumentationFile.Create";
    public const string DocumentationFileChange = "DocumentationFile.Change";
    public const string DocumentationFileDelete = "DocumentationFile.Delete";
    
    public const string DocumentView = "Document.View";
    public const string DocumentCreate = "Document.Create";
    public const string DocumentChange = "Document.Change";
    public const string DocumentDelete = "Document.Delete";
    
    public const string AccountView = "Account.View";
    public const string AccountCreate = "Account.Create";
    public const string AccountChange = "Account.Change";
    public const string AccountDelete = "Account.Delete";

    public static IEnumerable<string> EnumerateSecurables()
    {
        yield return DocumentationFileView;
        yield return DocumentationFileCreate;
        yield return DocumentationFileChange;
        yield return DocumentationFileDelete;
        
        yield return DocumentView;
        yield return DocumentCreate;
        yield return DocumentChange;
        yield return DocumentDelete;
        
        yield return AccountView;
        yield return AccountCreate;
        yield return AccountChange;
        yield return AccountDelete;
    }
}