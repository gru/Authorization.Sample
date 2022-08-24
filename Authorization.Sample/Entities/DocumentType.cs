using LinqToDB;
using LinqToDB.Mapping;

namespace Authorization.Sample.Entities;

[Table(Name = "document_types")]
public class DocumentType
{
    [Column(Name = "id", DataType = DataType.Long, IsPrimaryKey = true, CanBeNull = false)]
    public DocumentTypeId Id { get; set; }

    [Column(Name = "name", DataType = DataType.VarChar, Length = 255)]
    public string Name { get; set; }
}