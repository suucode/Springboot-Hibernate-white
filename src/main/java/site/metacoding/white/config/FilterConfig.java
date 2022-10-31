package site.metacoding.white.config;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration // IoC 컨테이너에 등록
public class FilterConfig {

    // 서버 실행시 IoC 등록
    @Bean
    public FilterRegistrationBean<HelloFilter> jwtAuthenticationFilterRegister() {
        log.debug("디버그 : 인증필터등록");
        FilterRegistrationBean<HelloFilter> bean = new FilterRegistrationBean<>(new HelloFilter());
        bean.addUrlPatterns("/hello"); // /hello라는 주소가 오면 필터가 실행됨
        return bean;
    }
}

@Slf4j
class HelloFilter implements Filter {

    // /hello 요청시 실행
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response; // 다운캐스팅 해야 쓸 수 있다

        if (req.getMethod().equals("POST")) {
            log.debug("디버그 : HelloFilter 실행됨");
        } else {
            log.debug("디버그 : POST요청이 아니어서 실행할 수 없습니다");
        }

        // chain.doFilter(request, response);
    }

}