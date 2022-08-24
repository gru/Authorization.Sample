using LinqToDB;
using LinqToDB.Mapping;

namespace Authorization.Sample.Entities;

[Table(Name = "bankusers")]
public class BankUser
{
    [Column(Name = "id", DataType = DataType.Long, IsPrimaryKey = true, CanBeNull = false)]
    public BankUserId Id { get; set; }
}