namespace Authorization.Permissions;

public static class Securables
{
    public const string DocumentationFileView = "DocumentationFile.View";
    public const string DocumentationFileManage = "DocumentationFile.Manage";
    
    public const string DocumentView = "Document.View";
    public const string DocumentManage = "Document.Manage";
    
    public const string AccountView = "Account.View";
    public const string AccountManage = "Account.Manage";

    public static IEnumerable<string> EnumerateSecurables()
    {
        yield return DocumentationFileView;
        yield return DocumentationFileManage;
        
        yield return DocumentView;
        yield return DocumentManage;
        
        yield return AccountView;
        yield return AccountManage;
    }
}