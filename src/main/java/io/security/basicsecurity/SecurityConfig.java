package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //메모리방식 유저등록
        auth.inMemoryAuthentication().withUser("user").password("{noop}1").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1").roles("SYS","USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1").roles("ADMIN","SYS","USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER") // user경로 접근시 "USER" 권한 유무체크
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();
        http
                .formLogin()
                //.loginPage("/loginPage") //사용자 정의 로그인 페이지
                .defaultSuccessUrl("/") //로그인 성공 후 이동 페이지
                .failureUrl("/login") //로그인 실패 후 이동 페이지
                .usernameParameter("userId") //아이디 파라미터명 설정
                .passwordParameter("passwd") //패스워드 파라미터명 설정
                .loginProcessingUrl("/login_proc") //로그인 Form Action Url
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        RequestCache requestCache = new HttpSessionRequestCache();
//                        SavedRequest savedRequest = requestCache.getRequest(request, response);
//                        String redirectUrl = savedRequest.getRedirectUrl();
//                        response.sendRedirect(redirectUrl);
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception : " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll();
        http
                .logout()
                .logoutUrl("/logout") //로그아웃처리 url
                .logoutSuccessUrl("/login") //로그아웃 성공 후 이동페이지
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me"); //로그아웃 후 쿠키삭제
        http
                .rememberMe()
                .rememberMeParameter("remember") //기본 파라미터명은 remember-me
                .tokenValiditySeconds(3600) // Default는 14일
                .alwaysRemember(false) //리멤버 미 기능이 활성화되지 않아도 항상 실행
                .userDetailsService(userDetailsService)
                ;

        http //동시세션제어
                .sessionManagement()
                .invalidSessionUrl("/invalid") //세션이 유효하지 않을 때 이동 할 페이지
                .maximumSessions(1) //최대 허용 가능 세션수 , -1 : 무제한 로그인 세션 허용
                .maxSessionsPreventsLogin(false) //동시 로그인 차단함, false: 기존세션만료(default)
                .expiredUrl("/expired"); //세션이 만료된 경우 이동할 페이지

        http //세션고정보호
                .sessionManagement()
                .sessionFixation().changeSessionId();

//        http //인증,인가 예외처리
//                .exceptionHandling()
//                .authenticationEntryPoint(new AuthenticationEntryPoint() {
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
//                        //response.sendRedirect("/login");
//                    }
//                })
//                .accessDeniedHandler(new AccessDeniedHandler() {
//                    @Override
//                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
//                        response.sendRedirect("/denied");
//                    }
//                });
        http //Default는 csrf사용
                .csrf();

        //SecurityContext 모드전략, 자식쓰레드에서 부모의 SecurityContext를 참조 가능하도록 설정
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }
}
