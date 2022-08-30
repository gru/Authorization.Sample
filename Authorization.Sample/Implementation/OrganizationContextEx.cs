namespace Authorization.Sample.Implementation;

public static class OrganizationContextEx
{
    public static string ToCasbinString(this OrganizationContext organizationContext)
    {
        return ToCasbinString(
            organizationContext?.BranchId, 
            organizationContext?.RegionalOfficeId,
            organizationContext?.OfficeId);
    }

    public static string ToCasbinString(long? branchId, long? regionalOfficeId, long? officeId)
    {
        static string WildcardIfNull(long? value) 
            => value == null ? "*" : value.ToString();

        return $"{WildcardIfNull(branchId)}/{WildcardIfNull(regionalOfficeId)}/{WildcardIfNull(officeId)}";
    }
}