package site.metacoding.white.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import site.metacoding.white.config.auth.JwtAuthenticationFilter;
import site.metacoding.white.config.auth.JwtAuthorizationFilter;
import site.metacoding.white.domain.UserRepository;

@Slf4j
@RequiredArgsConstructor
@Configuration // IoC 컨테이너에 등록
public class FilterConfig {

    private final UserRepository userRepository; // DI (스프링의 IoC 컨테이너에서 옴)

    // 서버 실행시 IoC 등록
    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtAuthenticationFilterRegister() {
        log.debug("디버그 : 인증필터등록");
        FilterRegistrationBean<JwtAuthenticationFilter> bean = new FilterRegistrationBean<>(
                new JwtAuthenticationFilter(userRepository)); // 서버가 실행될 때 필터에게 userRepository를 넘겨줄 수 있게됨
        bean.addUrlPatterns("/login"); // /hello라는 주소가 오면 필터가 실행됨
        bean.setOrder(1); // 인증필터가 1번째로 실행됨
        return bean;
    }

    @Bean
    public FilterRegistrationBean<JwtAuthorizationFilter> jwtAuthorizationFilterRegister() {
        log.debug("디버그 : 인가필터등록"); // 권한체크
        FilterRegistrationBean<JwtAuthorizationFilter> bean = new FilterRegistrationBean<>(
                new JwtAuthorizationFilter());
        bean.addUrlPatterns("/s/*"); // 원래 *은 2개달아야하는데 얘만 예외
        bean.setOrder(2); // 인가필터가 2번째로 실행됨
        return bean;
    }
}
