using System.Text.Json.Serialization;
using Authorization.Permissions;
using Authorization.Sample.Entities;
using Authorization.Sample.Implementation;
using Authorization.Sample.Services;
using LinqToDB.Configuration;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("Default");
var connectionOptions = new LinqToDBConnectionOptionsBuilder()
    .UseSQLite(connectionString)
    .Build();
builder.Services.AddSingleton(new DataContext(connectionOptions));

builder.Services.AddSingleton<IDemoService>(new DemoService(false));
builder.Services.AddSingleton<ICurrentUserService, CurrentUserService>();
builder.Services.AddSingleton<ICurrentDateService>(new CurrentDateService());
builder.Services.AddSingleton<IAuthorizationModelFactory<AuthorizationModel>, AuthorizationModelFactory>();
builder.Services.AddSingleton<IMatcher<ResourceAuthorizationRequest>, ResourceMatcher>();
builder.Services.AddSingleton<IMatcher<DocumentAuthorizationRequest>, DocumentMatcher>();
builder.Services.AddSingleton<IMatcher<AccountAuthorizationRequest>, AccountMatcher>();
builder.Services.AddSingleton<IFilter<Document, DefaultFilterRequest>, DocumentFilter>();
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
builder.Services.AddSingleton<IAuthorizationHandler, OpaAuthorizationHandler>();
builder.Services.AddSingleton<IOpaManager, OpaManager>();
builder.Services.AddSingleton<IOpaDataManager, OpaDataManager>();
builder.Services.AddHttpClient<IOpaClient, OpaHttpClient>()
    .ConfigureHttpClient(client =>
    {
        var url = builder.Configuration
            .GetValue<string>("OpaUrl");
        
        client.BaseAddress = new Uri(url);
    });

builder.Services.AddAuthorization(options =>
{
    var securables = new[]
    {
        Securables.DocumentationFileView,
        Securables.DocumentationFileCreate,
        Securables.DocumentationFileChange,
        Securables.DocumentationFileDelete
    };

    foreach (var securable in securables)
    {
        var split = securable.Split('.');
        var securableId = split[0];
        var permissionId = split[1];
        
        options.AddPolicy(securable, b =>
        {
            b.AddOpaRequirement("sample.resource", securableId, permissionId);
        });
    }
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.Services
    .GetRequiredService<DataContext>()
    .CreateTestData();

app.Services
    .GetRequiredService<IOpaDataManager>()
    .PushJsonDataFile("data.json");

app.Services
    .GetRequiredService<IOpaManager>()
    .PushPolicyFile("sample.resource", "sample.resource.rego")
    .PushPolicyFile("sample.document", "sample.document.rego");

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();