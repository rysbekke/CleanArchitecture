using Application.DTOs;
using Core.Entities;
using Application.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Application.Services
{
    public class AuthService : IAuthService
    {
        private readonly IUserRepository _userRepository;
        private readonly IConfiguration _configuration;

        public AuthService(IUserRepository userRepository, IConfiguration configuration)
        {
            _userRepository = userRepository;
            _configuration = configuration;
        }

        public async Task<AuthResponseDto> RegisterAsync(RegisterRequestDto registerDto)
        {
            var existingUser = await _userRepository.GetUserByUsernameAsync(registerDto.Username);
            if (existingUser != null)
                throw new Exception("User already exists");

            var user = new User
            {
                Username = registerDto.Username,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(registerDto.Password),
                RefreshToken = GenerateNewRefreshToken() // Инициализация RefreshToken
            };

            await _userRepository.AddUserAsync(user);
            // Сохраняем RefreshToken и его срок действия
            await _userRepository.SaveRefreshTokenAsync(user.Username, user.RefreshToken, DateTime.UtcNow.AddDays(7));

            return await AuthenticateAsync(new LoginRequestDto { Username = registerDto.Username, Password = registerDto.Password });
        }

        public async Task<AuthResponseDto> AuthenticateAsync(LoginRequestDto loginDto)
        {
            var user = await _userRepository.GetUserByUsernameAsync(loginDto.Username);
            if (user == null || !BCrypt.Net.BCrypt.Verify(loginDto.Password, user.PasswordHash))
                throw new Exception("Invalid credentials");

            var authResponse = GenerateTokens(user);
            user.RefreshToken = authResponse.RefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await _userRepository.UpdateUserAsync(user);

            return authResponse;
        }

        public async Task LogoutAsync(string refreshToken)
        {
            var user = await _userRepository.GetUserByRefreshTokenAsync(refreshToken);
            if (user == null)
                throw new Exception("Invalid refresh token");

            // Устанавливаем refresh token в null или генерируем новый, чтобы аннулировать старый
            user.RefreshToken = null; // Или можете создать новый токен
            await _userRepository.UpdateUserAsync(user); // Сохраняем изменения в базе данных
        }

        public async Task<AuthResponseDto> RefreshTokenAsync(string refreshToken)
        {
            var user = await _userRepository.GetUserByRefreshTokenAsync(refreshToken);
            if (user == null || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                throw new Exception("Invalid refresh token");
            }

            var newAccessToken = GenerateAccessToken(user);
            var newRefreshToken = GenerateNewRefreshToken();

            user.RefreshToken = newRefreshToken; // Обновляем RefreshToken
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7); // Обновляем срок действия
            await _userRepository.UpdateUserAsync(user); // Сохраняем пользователя с новым RefreshToken

            return new AuthResponseDto
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            };
        }

        private AuthResponseDto GenerateTokens(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration["JwtSettings:Secret"]);

            // Генерация Access Token
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                new Claim(ClaimTypes.Name, user.Username),
                }),
                Expires = DateTime.UtcNow.AddMinutes(30), // Время жизни Access Token
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var accessToken = tokenHandler.WriteToken(token);

            return new AuthResponseDto
            {
                AccessToken = accessToken,
                RefreshToken = GenerateNewRefreshToken()
            };
        }

        private string GenerateNewRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        public string GenerateAccessToken(User user)
        {
            var tokenExpiration = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["JwtSettings:AccessTokenExpiration"]));

            var claims = new[]
            {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username)
        };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:Secret"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["JwtSettings:Issuer"],
                audience: _configuration["JwtSettings:Audience"],
                claims: claims,
                expires: tokenExpiration,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
