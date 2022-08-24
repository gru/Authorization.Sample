namespace Authorization.Sample.Entities;

public class Document
{
    public long Id { get; set; }

    public long BranchId { get; set; }
    
    public long OfficeId { get; set; }
    
    public DocumentTypeId DocumentTypeId { get; set; }
}