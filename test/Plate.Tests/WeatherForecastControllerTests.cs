using Microsoft.AspNetCore.Mvc;
using Plate.Api.Controllers;

namespace Plate.Tests;

public class WeatherForecastControllerTests
{
    private readonly WeatherForecastController _weatherForecastController;
    private readonly CancellationToken _token = CancellationToken.None;


    [Fact]
    public async void Test1()
    {
        //_weatherForecastController = new WeatherForecastController();
        //var teams = (IEnumerable<WeatherForecast>)(await _weatherForecastController.Get(_token) as ObjectResult).Value;
        //
    }
}
