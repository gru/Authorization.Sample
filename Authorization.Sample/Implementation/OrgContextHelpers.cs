namespace Authorization.Sample.Implementation;

public static class OrgContextHelpers
{
    public static string ToOrgContextValue(long? value) => 
        value.HasValue ? value.ToString() : "*";
}