package site.metacoding.white.config.auth;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import site.metacoding.white.domain.User;
import site.metacoding.white.domain.UserRepository;
import site.metacoding.white.dto.ResponseDto;
import site.metacoding.white.dto.SessionUser;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthorizationFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;

        // 헤더의 Authorization 키값에 Bearer로 적힌 값이 있는지 체크
        String jwtToken = req.getHeader("Authorization");
        log.debug("디버그 : " + jwtToken);
        if (jwtToken == null) {
            customResponse("JWT토큰이 없어서 인가할 수 없습니다.", resp);
            return;
        }

        // 토큰 검증, 혹시모르니까 공백제거를 해줘야한다.
        jwtToken = jwtToken.replace("Bearer ", ""); // Bearer 옆에 공백주의!!!
        // jwtToken = jwtToken.trim(); // 앞뒤공백제거 -> 안해도됨..!
        try {
            DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512("뺑소니")).build().verify(jwtToken);// 순수한 JWT 검증
            Long userId = decodedJWT.getClaim("id").asLong();
            String username = decodedJWT.getClaim("username").asString();
            SessionUser sessionUser = new SessionUser(User.builder().id(userId).username(username).build());
            HttpSession session = req.getSession(); // HttpSession에서 꺼내쓸 수 있다
            session.setAttribute("sessionUser", sessionUser);
        } catch (Exception e) {
            customResponse("토큰 검증 실패", resp);
        }

        // DS 입장 혹은 Filter체인 타기
        chain.doFilter(req, resp);
    }

    private void customResponse(String msg, HttpServletResponse resp) throws IOException, JsonProcessingException {
        resp.setContentType("application/json; charset=utf-8");
        PrintWriter out = resp.getWriter(); // buffered write의 편한버전
        resp.setStatus(400);
        ResponseDto<?> responseDto = new ResponseDto<>(-1, msg, null);
        ObjectMapper om = new ObjectMapper();
        String body = om.writeValueAsString(responseDto);
        out.println(body);
        out.flush();
    }
}
