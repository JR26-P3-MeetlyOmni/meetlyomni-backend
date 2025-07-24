using System;

using Microsoft.AspNetCore.Mvc;

namespace MeetlyOmni.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class TestController : ControllerBase
    {
        // 故意的问题1: Controller 直接包含业务逻辑
        [HttpGet]
        public IActionResult GetUsers()
        {
            // 故意的问题2: 硬编码连接字符串
            var connectionString = "Server=localhost;Database=TestDB;User=admin;Password=123456;";

            // 故意的问题3: 没有异常处理的数据库操作
            var users = GetUsersFromDatabase(connectionString);

            // 故意的问题4: 直接返回敏感信息
            return Ok(new { Users = users, ConnectionString = connectionString });
        }

        // 故意的问题5: 同步方法中使用异步操作
        private List<string> GetUsersFromDatabase(string connectionString)
        {
            // 模拟数据库操作
            Task.Delay(1000).Wait(); // 应该使用 await
            return new List<string> { "user1", "user2" };
        }

        // 故意的问题6: 缺少输入验证
        [HttpPost]
        public IActionResult CreateUser(string userName, string email)
        {
            // 直接使用用户输入，没有验证
            var user = $"Creating user: {userName} with email: {email}";
            return Ok(user);
        }
    }
}
