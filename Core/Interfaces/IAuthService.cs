using Core.DTOs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core.Interfaces
{
    public interface IAuthService
    {
        Task<AuthResponseDto> RegisterAsync(RegisterRequestDto registerDto);
        Task<AuthResponseDto> AuthenticateAsync(LoginRequestDto loginDto);
        Task<AuthResponseDto> RefreshTokenAsync(string refreshToken);
    }
}
