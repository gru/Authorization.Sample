using System.Text.Json.Serialization;
using Authorization.Sample.Entities;
using Authorization.Sample.Implementation;
using Authorization.Sample.Services;
using Casbin;
using LinqToDB.Configuration;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionOptions = new LinqToDBConnectionOptionsBuilder()
    .UseSQLite("Data Source=:memory:")
    .Build();
builder.Services.AddSingleton(new DataContext(connectionOptions));
builder.Services.AddSingleton(new CasbinAuthorizationModelOptions());
builder.Services.AddSingleton<IAuthorizationModelFactory<IEnforcer>, CasbinAuthorizationModelFactory>();
builder.Services.AddSingleton<IDemoService>(new DemoService(false));
builder.Services.AddSingleton<ICurrentUserService, CurrentUserService>();
builder.Services.AddSingleton<ICurrentDateService>(new CurrentDateService());
builder.Services.AddSingleton<IMatcher<ResourceAuthorizationRequest>, ResourceCasbinMatcher>();
builder.Services.AddSingleton<IMatcher<DocumentAuthorizationRequest>, DocumentCasbinMatcher>();
builder.Services.AddSingleton<IMatcher<AccountAuthorizationRequest>, AccountCasbinMatcher>();
builder.Services.AddSingleton<IFilter<Document, DefaultFilterRequest>, DocumentCasbinFilter>();
builder.Services.AddSingleton<IFilter<DocumentationFileCategory, DefaultFilterRequest>, DocumentationFileCategoryFilter>();
builder.Services.AddSingleton<AuthorizationEnforcer>();

builder.Services.AddHttpContextAccessor();
builder.Services.AddControllers().AddJsonOptions(opts =>
{
    opts.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
});
builder.Services.AddAuthentication(opts =>
{
    opts.DefaultScheme = AuthSchemas.RequestQueryScheme;
}).AddScheme<RequestQueryOptions, RequestQueryAuthenticationHandler>(AuthSchemas.RequestQueryScheme, _ => {});
builder.Services.AddAuthorization();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.Services
    .GetRequiredService<DataContext>()
    .CreateTestData();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();