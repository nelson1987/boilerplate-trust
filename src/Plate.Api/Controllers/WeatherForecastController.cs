using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;

namespace Plate.Api.Controllers;
[ApiController]
[Route("api/[controller]")]
[EnableRateLimiting("fixed-by-ip")]
[Produces("application/json")]
[Consumes("application/json")]
public class WeatherForecastController : ControllerBase
{
    private readonly ILogger<WeatherForecastController> _logger;
    private readonly ISummary _summaries;
    private readonly IUserRepository _userRepository;

    public WeatherForecastController(ILogger<WeatherForecastController> logger,
        ISummary summaries,
        IUserRepository userRepository)
    {
        _logger = logger;
        _summaries = summaries;
        _userRepository = userRepository;
    }

    [HttpPost]
    [Route("/login")]
    [AllowAnonymous]
    public async Task<ActionResult<dynamic>> Authenticate([FromBody] LoginAccountCommand model)
    {
        var user = await _userRepository.GetPerson(model.Username, model.Password);

        if (user == null)
            return NotFound(new { message = "Usuário ou senha inválidos" });

        var token = TokenService.GenerateToken(user);
        user.Password = "";
        return new
        {
            user,
            token
        };
    }

    [HttpGet]
    public async Task<ActionResult> Get(CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Started {0}", nameof(Get));
        var sumaries = await _summaries.GetSummaries(cancellationToken);
        return Ok(Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = sumaries[Random.Shared.Next(sumaries.Length)]
        }));
    }

    [HttpGet]
    [Route("authenticated")]
    [Authorize]
    public string Authenticated()
    {
        var identity = (ClaimsIdentity?)User.Identity!;
        var roles = identity.Claims
            .Where(c => c.Type == ClaimTypes.Role)
            .Select(c => c.Value);

        return $"Autenticado: {identity.Name}\nRole: {string.Join(",", roles.ToList())}";
    }

    [HttpGet]
    [Route("/employee")]
    [Authorize(Roles = "employee,manager")]
    public string Employee()
    {
        var identity = (ClaimsIdentity?)User.Identity!;
        return $"Funcionário: {identity.Name}";
    }

    [HttpGet]
    [Route("/manager")]
    [Authorize(Roles = "manager")]
    public string Manager()
    {
        var identity = (ClaimsIdentity?)User.Identity!;
        return $"Gerente: {identity.Name}";
    }
}

public record WeatherForecast
{
    public DateOnly Date { get; set; }

    public int TemperatureC { get; set; }

    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);

    public string? Summary { get; set; }
}

public record User
{
    public int Id { get; set; }
    public string Username { get; set; }
    public string Password { get; set; }
    public string Role { get; set; }
}

public record LoginAccountCommand(string Username, string Password);

public interface ISummary
{
    Task<string[]> GetSummaries(CancellationToken cancellationToken = default);
}

public class Summary : ISummary
{
    public async Task<string[]> GetSummaries(CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        });
    }
}

public interface IUserRepository
{
    Task<User?> GetPerson(string login, string password, CancellationToken cancellationToken = default);
}

public class UserRepository : IUserRepository
{
    private readonly User[] _users = new[] {
        new User { Id = 1, Username = "batman", Password = "batman", Role = "manager" },
        new User { Id = 2, Username = "robin", Password = "robin", Role = "employee" }
    };
    public async Task<User?> GetPerson(string login, string password, CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(_users.FirstOrDefault(x => x.Username.Equals(login) && x.Password.Equals(password)));
    }
}

public static class Settings
{
    public static readonly string Secret = "fedaf7d8863b48e197b9287d492b708e";
}

public static class TokenService
{
    public static string GenerateToken(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(Settings.Secret);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[]
            {
                new(ClaimTypes.Name, user.Username),
                new(ClaimTypes.Role, user.Role)
            }),
            Expires = DateTime.UtcNow.AddHours(2),
            SigningCredentials =
                new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}

public static class Dependencies
{
    public static IServiceCollection AddSummaries(this IServiceCollection services)
    {
        services.AddScoped<ISummary, Summary>();
        services.AddScoped<IUserRepository, UserRepository>();
        return services;
    }

    public static IServiceCollection AddRateLimit(this IServiceCollection services)
    {
        services.AddRateLimiter(rateLimiterOptions =>
        {
            rateLimiterOptions.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            rateLimiterOptions.AddTokenBucketLimiter("token", options =>
            {
                options.TokenLimit = 1000;
                options.ReplenishmentPeriod = TimeSpan.FromHours(1);
                options.TokensPerPeriod = 700;
                options.AutoReplenishment = true;
            });

            rateLimiterOptions.AddPolicy("fixed-by-ip", httpContext =>
                RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: httpContext.Connection.RemoteIpAddress?.ToString(),
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 5,
                        Window = TimeSpan.FromSeconds(10)
                    }));
        });
        return services;
    }

    public static IServiceCollection AddUserAuthentication(this IServiceCollection services)
    {
        var key = Encoding.ASCII.GetBytes(Settings.Secret);
        services.AddAuthentication(x =>
        {
            x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(x =>
        {
            x.RequireHttpsMetadata = false;
            x.SaveToken = true;
            x.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false
            };
        });
        return services;
    }

    public static IServiceCollection AddSwaggerGeneration(this IServiceCollection services)
    {
        services.AddSwaggerExamplesFromAssemblyOf(typeof(LoginAccountCommandExample));
        services.AddSwaggerGen(c =>
        {
            c.EnableAnnotations();
            c.ExampleFilters();
            c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
            {
                Name = "Authorization",
                Type = SecuritySchemeType.ApiKey,
                Scheme = "Bearer",
                BearerFormat = "JWT",
                In = ParameterLocation.Header,
                Description = "JWT Authorization header using the Bearer scheme. \r\n\r\n " +
                "Enter 'Bearer' [space] and then your token in the text input below.\r\n\r\n" +
                "Example: \"Bearer 1safsfsdfdfd\"",
            });
            c.AddSecurityRequirement(new OpenApiSecurityRequirement {
                {
                new OpenApiSecurityScheme {
                    Reference = new OpenApiReference {
                        Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                    }
                    },
                    Array.Empty<string>()
                }
            });
        });
        return services;
    }
}

public class LoginAccountCommandExample : IMultipleExamplesProvider<LoginAccountCommand>
{
    public IEnumerable<SwaggerExample<LoginAccountCommand>> GetExamples()
    {
        yield return SwaggerExample.Create("Manager", new LoginAccountCommand("batman", "batman"));
        yield return SwaggerExample.Create("Employee", new LoginAccountCommand("robin", "robin"));
    }
}
