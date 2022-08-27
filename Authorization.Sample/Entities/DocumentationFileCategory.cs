using LinqToDB;
using LinqToDB.Mapping;

namespace Authorization.Sample.Entities;

[Table(Name = "documentation_file_categories")]
public class DocumentationFileCategory
{
    [Column(Name = "id", DataType = DataType.Int32, IsPrimaryKey = true, IsIdentity = true, CanBeNull = false)]
    public long Id { get; set; }

    [Column(Name = "category_type", DataType = DataType.Int16, CanBeNull = false)]
    public DocumentationFileCategoryType CategoryType { get; set; }

    [Column(Name = "name", DataType = DataType.VarChar, Length = 255, CanBeNull = false)]
    public string Name { get; set; }
}