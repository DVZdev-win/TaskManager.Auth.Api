using Microsoft.EntityFrameworkCore;

namespace TaskManager.Api.Data
{
    public static class DataExtentions
    {
        public static void AddTaskManagerDb(this WebApplicationBuilder builder)
        {
            var connString = builder.Configuration.GetConnectionString("DefaultConnection");

            builder.Services.AddSqlite<ApplicationDbContext>(connString);
        }
    }
}
