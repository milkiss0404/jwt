package com.example.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //세션방식은 세션이 고정이기때문에 csrf공격을 방어해야하지만 jwt방식은 세션을 stateless 상태로 관리하기떄문에
        //관리하기 떄문에 disable 처리해준다
        http.csrf((auth) -> auth.disable());

        http
                .formLogin((auth) -> auth.disable());

        //http basic 인증 방식 disable
        http
                .httpBasic((auth) -> auth.disable());

        //경로별 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated()); // anyRequest = 나머지 요청에는 로그인된
                                                        // authenticated =사용자만 접근가능하게

        //세션 설정
        // TODO: jwt 방식에서는  세션을 stateless 하게 관리해주어야 한다.  이부분이 꼭필요함
        //인증(Authentication)은 등록된 사용자인지 확인하는 과정이고,
        //인가(Authorization)는 권한이 있는 사용자인지 확인하는 과정이다.
        //
        //http 특성 때문에 인증, 인가 과정은 꼭 필요하다.
        //http는 요청이 들어오면 응답하는 구조인데, 응답 이후 상태가 저장되지 않기 때문에(stateless),
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        return http.build();
    }



    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

}
