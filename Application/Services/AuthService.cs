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
                RefreshToken = GenerateNewRefreshToken() // Убедитесь, что вы инициализируете значение
            };
            await _userRepository.AddUserAsync(user);

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

        public async Task<AuthResponseDto> RefreshTokenAsync(string refreshToken)
        {
            //var user = await _userRepository.GetUserByRefreshTokenAsync(refreshToken);
            //if (user == null || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            //    throw new Exception("Invalid refresh token");

            //return GenerateTokens(user);
            var user = await _userRepository.GetUserByRefreshTokenAsync(refreshToken);
            if (user == null)
            {
                throw new Exception("Invalid refresh token");
            }

            // Генерируем новый токен
            var newAccessToken = GenerateAccessToken(user);
            var newRefreshToken = GenerateNewRefreshToken();

            user.RefreshToken = newRefreshToken; // Устанавливаем новый refresh token
            await _userRepository.UpdateUserAsync(user); // Сохраняем пользователя с новым refresh token
            //await _unitOfWork.SaveAsync(); // Сохраняем изменения

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

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, user.Username)
                }),
                Expires = DateTime.UtcNow.AddMinutes(30),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var accessToken = tokenHandler.WriteToken(token);

            return new AuthResponseDto
            {
                AccessToken = accessToken,
                RefreshToken = Guid.NewGuid().ToString() // Could be a JWT or any unique identifier
            };
        }

        private string GenerateNewRefreshToken()
        {
            var randomNumber = new byte[32]; // Размер токена
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber); // Генерируем случайные байты
                return Convert.ToBase64String(randomNumber); // Преобразуем байты в строку
            }
        }

        public string GenerateAccessToken(User user)
        {
            // Устанавливаем время истечения токена
            var tokenExpiration = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["JwtSettings:AccessTokenExpiration"]));

            // Создаем claims для токена
            var claims = new[]
            {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username)
            // Добавьте другие claims по необходимости
        };

            // Генерируем ключ шифрования
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:Secret"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // Создаем токен
            var token = new JwtSecurityToken(
                issuer: _configuration["JwtSettings:Issuer"],
                audience: _configuration["JwtSettings:Audience"],
                claims: claims,
                expires: tokenExpiration,
                signingCredentials: creds
            );

            // Возвращаем токен как строку
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
