using System.Text.Json.Serialization;
using Authorization.Sample.Entities;
using Authorization.Sample.Implementation;
using Authorization.Sample.Services;
using LinqToDB.Configuration;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionOptions = new LinqToDBConnectionOptionsBuilder()
    .UseSQLite("Data Source=:memory:")
    .Build();
builder.Services.AddSingleton(new DataContext(connectionOptions));
builder.Services.AddSingleton<IDemoService>(new DemoService(true));
builder.Services.AddSingleton<ICurrentUserService, CurrentUserService>();
builder.Services.AddSingleton<ICurrentDateService>(new CurrentDateService());
builder.Services.AddSingleton<IAuthorizationModelFactory<AuthorizationModel>, AuthorizationModelFactory>();
builder.Services.AddSingleton<IMatcher<ResourceAuthorizationRequest>, ResourceMatcher>();
builder.Services.AddSingleton<IMatcher<DocumentAuthorizationRequest>, DocumentMatcher>();
builder.Services.AddSingleton<IMatcher<AccountAuthorizationRequest>, AccountMatcher>();
builder.Services.AddSingleton<IFilter<Document, DocumentFilterRequest>, DocumentFilter>();
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