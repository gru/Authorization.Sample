using LinqToDB;
using LinqToDB.Mapping;

namespace Authorization.Sample.Entities;

[Table(Name = "accounts")]
public class Account
{
    [Column(Name = "id", DataType = DataType.Int32, IsPrimaryKey = true, IsIdentity = true, CanBeNull = false)]
    public long Id { get; set; }

    [Column(Name = "number", DataType = DataType.VarChar, Length = 20, CanBeNull = false)]
    public string Number { get; set; }

    [Column(Name = "gl2", DataType = DataType.VarChar, Length = 5, CanBeNull = false)]
    public string GL2 { get; set; }
}