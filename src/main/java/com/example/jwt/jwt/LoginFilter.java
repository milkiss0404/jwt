package com.example.jwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

//UsernamePasswordAuthenticationFilter란 Form based Authentication 방식으로
//인증을 진행할 때 아이디, 패스워드 데이터를 파싱하여 인증 요청을 위임하는 필터이다.
//쉽게 설명하자면 유저가 로그인 창에서 Login을 시도할 때 보내지는 요청에서 아이디(username)와
// 패스워드(password) 데이터를 가져온 후 인증을 위한 토큰을 생성 후 인증을 다른 쪽에 위임하는 역할을 하는 필터이다.
//Spring Boot 기반의 HttpSecurity를 설정하는 코드에서 http.formLogin(); 을
// 사용하면 시큐리티에서는 기본적으로 UsernamePasswordAuthenticationFilter 을 사용하게 된다.


//인증 요청을 가로채고, Authentication 객체를 만든 뒤 AuthenticationManager에게 인증 역할을 위임한다.

@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = obtainUsername(request); //obtainUsername라는 메소드가있음
        String password = obtainUsername(request);

        //TODO:스프링 시큐리티에서 username과 password를 검증하기 위해서는 token에 담아야 함
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        //token에 담은 검증을 위한 AuthenticationManager로 전달
        return authenticationManager.authenticate(authToken);

    }
    // TODO:로그인 성공시 실행하는 메소드 (여기서 JWT를 발급하면 됨)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
    }

    // TODO: 로그인 실패시 실행하는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
    }
}
