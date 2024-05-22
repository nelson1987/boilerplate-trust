using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using AutoMapper;
using FluentResults;
using FluentValidation;
using MediatR;
using MediatR.Extensions.FluentValidation.AspNetCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Serilog;
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
    private readonly ISummaryRepository _summaries;
    private readonly IUserRepository _userRepository;
    private readonly IValidator<CreateTransferCommand> _validator;
    private readonly IMediator _handler;

    public WeatherForecastController(ILogger<WeatherForecastController> logger,
        ISummaryRepository summaries,
        IUserRepository userRepository,
        IValidator<CreateTransferCommand> validator,
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
    public async Task<ActionResult<Result>> Post([FromBody] CreateTransferRequest request, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Started {0}", nameof(Post));
        var command = request.MapTo<CreateTransferCommand>();
        command.Username = User.GetUserName();

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
    public async Task<ActionResult> Authenticated(CancellationToken cancellationToken = default)
    {
        return Ok($"Autenticado: {User.GetUserName()}\nRole: {string.Join(",", User.GetRoles())}");
    }

    [HttpGet]
    [Route("/employee")]
    [Authorize(Roles = "employee,manager")]
    public async Task<ActionResult> Employee(CancellationToken cancellationToken = default)
    {
        return Ok($"Funcionário: {User.GetUserName()}");
    }

    [HttpGet]
    [Route("/manager")]
    [Authorize(Roles = "manager")]
    public async Task<ActionResult> Manager(CancellationToken cancellationToken = default)
    {
        return Ok($"Gerente: {User.GetUserName()}");
    }
}

public static class IdentityExtensions
{
    public static string GetUserName(this ClaimsPrincipal User)
    {
        var identity = (ClaimsIdentity?)User.Identity!;
        return identity.Name!;
    }

    public static string[] GetRoles(this ClaimsPrincipal User)
    {
        var identity = (ClaimsIdentity?)User.Identity!;
        return identity.Claims
            .Where(c => c.Type == ClaimTypes.Role)
            .Select(c => c.Value)
            .ToArray();
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

public record CreateTransferCommand : IRequest
{
    public string Username { get; set; }
    public decimal Amount { get; set; }
}

public record CreateTransferRequest(decimal Amount);

public class CreateAccountCommandValidator : AbstractValidator<CreateTransferCommand>
{
    public CreateAccountCommandValidator()
    {
        RuleFor(x => x.Username).NotEmpty();
    }
}

public class CreateTransferRequestValidator : AbstractValidator<CreateTransferRequest>
{
    public CreateTransferRequestValidator()
    {
        RuleFor(x => x.Amount).NotEmpty();
    }
}

public interface ISummaryRepository
{
    Task<string[]> GetSummaries(CancellationToken cancellationToken = default);
}

public class Summary : ISummaryRepository
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
    Task Handle(CreateTransferCommand request, CancellationToken cancellationToken = default);
}

public class CreateAccountHandler : ICreateAccountHandler
{
    public Task Handle(CreateTransferCommand request, CancellationToken cancellationToken = default)
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
        services.AddScoped<ISummaryRepository, Summary>();
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<IValidator<CreateTransferRequest>, CreateTransferRequestValidator>();
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
        services.AddMediatR(cfg =>
        {
            cfg.RegisterServicesFromAssembly(domainAssembly);
            cfg.AddOpenBehavior(typeof(LoggingBehavior<,>));
            cfg.AddOpenBehavior(typeof(ValidationBehavior<,>));
        });
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
        CreateMap<CreateTransferRequest, CreateTransferCommand>();
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

public class CreateAccountCommandHandler : IRequestHandler<CreateTransferCommand>
{
    public async Task Handle(CreateTransferCommand request, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}

public class LoggingBehavior<TRequest, TResponse> : IPipelineBehavior<TRequest, TResponse>
    where TRequest : class
    where TResponse : Result
{
    private readonly ILogger<LoggingBehavior<TRequest, TResponse>> _logger;

    public LoggingBehavior(ILogger<LoggingBehavior<TRequest, TResponse>> logger)
    {
        _logger = logger;
    }

    public async Task<TResponse> Handle(TRequest request, RequestHandlerDelegate<TResponse> next, CancellationToken cancellationToken)
    {
        var correlationId = Guid.NewGuid();
        string requestName = typeof(TRequest).Name;
        var requestJson = JsonSerializer.Serialize(request);
        _logger.LogInformation("Started handling {RequestName} - {CorrelationID} : {Request}", requestName, correlationId, requestJson);
        TResponse result = await next();
        var resultJson = JsonSerializer.Serialize(request);
        if (result.IsSuccess)
        {
            _logger.LogInformation(
                "Ended handling {RequestName} - {CorrelationID} : {Request}", requestName, correlationId, resultJson);
        }
        else
        {
            //using (LogContext.PushProperty("Error", result.Error, true))
            //{
            _logger.LogError(
                "Ended handling {RequestName} with error - {CorrelationID} : {Request}", requestName, correlationId, resultJson);
            //}
        }
        return result;
    }
}
public class ValidationBehavior<TRequest, TResponse>(IEnumerable<IValidator<TRequest>> validators)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : class
{
    public async Task<TResponse> Handle(TRequest request, RequestHandlerDelegate<TResponse> next, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(next);

        if (validators.Any())
        {
            var context = new ValidationContext<TRequest>(request);

            var validationResults = await Task.WhenAll(
                validators.Select(v =>
                    v.ValidateAsync(context, cancellationToken))).ConfigureAwait(false);

            var failures = validationResults
                .Where(r => r.Errors.Count > 0)
                .SelectMany(r => r.Errors)
                .ToList();

            if (failures.Count > 0)
                throw new FluentValidation.ValidationException(failures);
        }
        return await next().ConfigureAwait(false);
    }
}

public class GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        var problemDetails = new ProblemDetails();
        problemDetails.Instance = httpContext.Request.Path;

        if (exception is FluentValidation.ValidationException fluentException)
        {
            problemDetails.Title = "one or more validation errors occurred.";
            problemDetails.Type = "https://tools.ietf.org/html/rfc7231#section-6.5.1";
            httpContext.Response.StatusCode = StatusCodes.Status400BadRequest;
            List<string> validationErrors = new List<string>();
            foreach (var error in fluentException.Errors)
            {
                validationErrors.Add(error.ErrorMessage);
            }
            problemDetails.Extensions.Add("errors", validationErrors);
        }

        else
        {
            problemDetails.Title = exception.Message;
        }

        logger.LogError("{ProblemDetailsTitle}", problemDetails.Title);

        problemDetails.Status = httpContext.Response.StatusCode;
        await httpContext.Response.WriteAsJsonAsync(problemDetails, cancellationToken).ConfigureAwait(false);
        return true;
    }
}
