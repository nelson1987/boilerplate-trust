using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.RateLimiting;
using AutoMapper;
using FluentValidation;
using MediatR;
using MediatR.Extensions.FluentValidation.AspNetCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Serilog;
using Serilog.Context;
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
    private readonly IValidator<CreateAccountCommand> _validator;
    private readonly IMediator _handler;

    public WeatherForecastController(ILogger<WeatherForecastController> logger,
        ISummary summaries,
        IUserRepository userRepository,
        IValidator<CreateAccountCommand> validator,
        IMediator handler)
    {
        _logger = logger;
        _summaries = summaries;
        _userRepository = userRepository;
        _validator = validator;
        _handler = handler;
    }

    [HttpPost]
    [Route("/login")]
    [AllowAnonymous]
    [SwaggerRequestExample(typeof(LoginAccountCommand), typeof(LoginAccountCommandExample))]
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

    [HttpPost]
    public async Task<ActionResult> Post([FromBody] CreateAccountRequest request, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Started {0}", nameof(Post));
        var command = request.MapTo<CreateAccountCommand>();
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        if (!validationResult.IsValid)
            return UnprocessableEntity(validationResult.Errors);

        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        await _handler.Send(command, cancellationToken);

        return Created();
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

public record CreateAccountCommand(string Username, string Password) : IRequest;

public record CreateAccountRequest(string Username, string Password);

public class CreateAccountCommandValidator : AbstractValidator<CreateAccountCommand>
{
    public CreateAccountCommandValidator()
    {
        RuleFor(x => x.Username).NotEmpty();
    }
}

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
        return await Task.FromResult(_users.FirstOrDefault(x =>
                                                string.Equals(x.Username, login, StringComparison.OrdinalIgnoreCase) &&
                                                string.Equals(x.Password, password, StringComparison.OrdinalIgnoreCase)));
    }
}

public interface ICreateAccountHandler
{
    Task Handle(CreateAccountCommand request, CancellationToken cancellationToken = default);
}

public class CreateAccountHandler : ICreateAccountHandler
{
    public Task Handle(CreateAccountCommand request, CancellationToken cancellationToken = default)
    {
        throw new NotImplementedException();
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
        services.AddScoped<IValidator<CreateAccountCommand>, CreateAccountCommandValidator>();
        services.AddScoped<ICreateAccountHandler, CreateAccountHandler>();
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

    public static IServiceCollection AddAutoMapping(this IServiceCollection services)
    {
        var configuration = new MapperConfiguration(cfg =>
        {
            cfg.AddProfile<AccountMapper>();
        });

        var mapper = new Mapper(configuration);
        AutoMapperExtension.Initialize(mapper);
        services.AddSingleton(mapper);
        return services;
    }

    public static IServiceCollection AddMediator(this IServiceCollection services)
    {
        var domainAssembly = typeof(CreateAccountCommandHandler).Assembly;
        // Add MediatR
        services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(domainAssembly));
        //Add FluentValidation
        services.AddFluentValidation(new[] { domainAssembly });
        return services;
    }
    public static ILoggingBuilder AddLogging(this ILoggingBuilder logging, IConfiguration configuration)
    {
        var logger = new LoggerConfiguration()
            .ReadFrom.Configuration(configuration)
            .Enrich.FromLogContext()
            .CreateLogger();
        logging.ClearProviders();
        logging.AddSerilog(logger);
        return logging;
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

public static class AutoMapperExtension
{
    private static IMapper _instance;

    public static void Initialize(IMapper instance)
    {
        _instance = instance;
    }

    public static TDestination MapTo<TDestination>(this object obj)
    {
        return _instance.Map<TDestination>(obj);
    }
}

public class AccountMapper : Profile
{
    public AccountMapper()
    {
        CreateMap<CreateAccountRequest, CreateAccountCommand>();
    }
}

public interface IAccountRepository
{
    string GetContaByUser(string userName);
}

public class Transferencia
{
    public readonly IAccountRepository _userRepository;
    public void Init(string userName, decimal valor, string contaEmissora, string numeroCheque)
    {
        var contaCliente = _userRepository.GetContaByUser(userName);
        var transacao = TransacaoFactory.Create(contaCliente, numeroCheque);
        var notificarCliente = "Depósito realizado com sucesso.";

    }
}

public record Transacao(string ContaCliente, string NumeroCheque, DateTime DataTransacao);

public static class TransacaoFactory
{
    public static Transacao Create(string contaCliente, string numeroCheque)
    {
        return new Transacao(contaCliente, numeroCheque, DateTime.Now);
    }
}

public class CreateAccountCommandHandler : IRequestHandler<CreateAccountCommand>
{
    public async Task Handle(CreateAccountCommand request, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}
public class LoggingBehavior<TRequest, TResponse> : IPipelineBehavior<TRequest, TResponse>
{
    private readonly ILogger<LoggingBehavior<TRequest, TResponse>> _logger;

    public LoggingBehavior(ILogger<LoggingBehavior<TRequest, TResponse>> logger)
    {
        _logger = logger;
    }

    public async Task<TResponse> Handle(TRequest request, RequestHandlerDelegate<TResponse> next, CancellationToken cancellationToken)
    {
        string requestName = typeof(TRequest).Name;
        _logger.LogInformation("Started handling {RequestName}", requestName);
        TResponse result = await next();
        //if (result.IsSuccess)
        //{
            _logger.LogInformation(
                "Completed handling {RequestName}", requestName);
        //}
        //else
        //{
        //    using (LogContext.PushProperty("Error", result.Error, true))
        //    {
        //        _logger.LogError(
        //            "Completed request {RequestName} with error", requestName);
        //    }
        //}
        return result;
    }
}
