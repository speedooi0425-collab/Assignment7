using Microsoft.Data.Sqlite;
using SafeVault.Models;

namespace SafeVault.Services
{
    public class DatabaseService
    {
        private readonly string _connectionString = "Data Source=SafeVault.db";

        public async Task<User> GetUserSecurely(string username)
        {
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();

            // PREVENTING SQL INJECTION: Using parameters (@name) instead of string concatenation
            var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, Username, Role FROM Users WHERE Username = @name";
            command.Parameters.AddWithValue("@name", username);

            using var reader = await command.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                return new User {
                    Id = reader.GetInt32(0),
                    Username = reader.GetString(1),
                    Role = reader.GetString(2)
                };
            }
            return null;
        }
    }
}
