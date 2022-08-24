using LinqToDB;
using LinqToDB.Mapping;

namespace Authorization.Sample.Entities;

[Table(Name = "documents")]
public class Document
{
    [Column(Name = "id", DataType = DataType.Int32, IsPrimaryKey = true, IsIdentity = true, CanBeNull = false)]
    public long Id { get; set; }

    [Column(Name = "branch_id", DataType = DataType.Long, CanBeNull = false)]
    public long BranchId { get; set; }
    
    [Column(Name = "office_id", DataType = DataType.Long, CanBeNull = false)]
    public long OfficeId { get; set; }
    
    [Column(Name = "document_type_id", DataType = DataType.Long, CanBeNull = false)]
    public DocumentTypeId DocumentTypeId { get; set; }
}