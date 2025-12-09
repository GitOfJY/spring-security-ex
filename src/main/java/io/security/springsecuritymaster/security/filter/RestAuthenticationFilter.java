package io.security.springsecuritymaster.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.springsecuritymaster.domain.dto.AccountDto;
import io.security.springsecuritymaster.token.RestAuthenticationToken;
import io.security.springsecuritymaster.util.WebUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import java.io.IOException;

public class RestAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    // 기본 UsernamePasswordAuthenticationFilter는 form-data만 처리
    // JSON body를 읽으려면 커스텀 필터가 필요 > RestAuthenticationFilter 생성

    /*
    POST /api/login (JSON body)
       ↓
    RestAuthenticationFilter (커스텀 필터)
       ↓
    AuthenticationManager
       ↓
    AuthenticationProvider (실제 인증 로직)
       ↓
    인증 성공/실패
    * */

    private final ObjectMapper objectMapper = new ObjectMapper();

    public RestAuthenticationFilter() {
        super(new AntPathRequestMatcher("/api/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException {

        if (!HttpMethod.POST.name().equals(request.getMethod()) || !WebUtil.isAjax(request)) {
            throw new IllegalArgumentException("Authentication method not supported");
        }

        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);

        if (!StringUtils.hasText(accountDto.getUsername()) || !StringUtils.hasText(accountDto.getPassword())) {
            throw new AuthenticationServiceException("Username or Password not provided");
        }
        RestAuthenticationToken token = new RestAuthenticationToken(accountDto.getUsername(),accountDto.getPassword());

        return this.getAuthenticationManager().authenticate(token);
    }

}
