using Xunit;
using SafeVault.Services;

namespace SafeVault.Tests
{
    public class SecurityTests
    {
        [Fact]
        public async Task DatabaseQuery_Should_HandleSpecialCharacters_Securely()
        {
            // Arrange
            var service = new DatabaseService();
            string maliciousInput = "' OR 1=1; --";

            // Act
            var result = await service.GetUserSecurely(maliciousInput);

            // Assert: Parameterization ensures the input is treated as a string, not a command.
            Assert.Null(result); 
        }
    }
}
