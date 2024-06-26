using System.IO.Compression;
using Microsoft.AspNetCore.ResponseCompression;
using Plate.Api.Controllers;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.AddLogging(builder.Configuration);
builder.Services.Configure<GzipCompressionProviderOptions>(options =>
                    {
                        options.Level = CompressionLevel.Optimal;
                    })
                .AddResponseCompression(options =>
                    {
                        options.Providers.Add<GzipCompressionProvider>();
                    })
                .AddSummaries()
                .AddRateLimit()
                .AddUserAuthentication()
                .AddSwaggerGeneration()
                .AddRouting(options => options.LowercaseUrls = true)
                .AddAutoMapping()
                .AddMediator()
                .AddPersistence(builder.Configuration)
                .AddMassTransit();
// Add services to the container.

builder.Services.AddControllers()
                .AddJsonOptions(options => options.JsonSerializerOptions.PropertyNamingPolicy = null);
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.UseRateLimiter();
app.Run();

public partial class Program
{ }
