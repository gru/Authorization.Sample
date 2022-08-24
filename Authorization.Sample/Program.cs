using Authorization.Sample;
using Authorization.Sample.Entities;
using Authorization.Sample.Implementation;
using Authorization.Sample.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddSingleton(new DataContext());
builder.Services.AddSingleton<ICurrentUserService, CurrentUserService>();
builder.Services.AddSingleton<ICurrentDateService>(new CurrentDateService());
builder.Services.AddSingleton<IAuthorizationModelFactory<ResourceAuthorizationModel>, ResourceAuthorizationModelFactory>();
builder.Services.AddSingleton<IAuthorizationModelFactory<DocumentAuthorizationModel>, DocumentAuthorizationModelFactory>();
builder.Services.AddSingleton<IMatcher<ResourceAuthorizationRequest>, ResourcePermissionMatcher>();
builder.Services.AddSingleton<IMatcher<DocumentAuthorizationRequest>, DocumentMatcher>();
builder.Services.AddSingleton<IFilter<Document, DocumentFilterRequest>, DocumentFilter>();
builder.Services.AddSingleton<AuthorizationEnforcer>();

builder.Services.AddHttpContextAccessor();
builder.Services.AddControllers();
builder.Services.AddAuthentication(opts =>
{
    opts.DefaultScheme = AuthSchemas.RequestQueryScheme;
}).AddScheme<RequestQueryOptions, RequestQueryAuthenticationHandler>(AuthSchemas.RequestQueryScheme, _ => {});
builder.Services.AddAuthorization();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();