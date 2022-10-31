package site.metacoding.white.config.auth;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Date;
import java.util.Optional;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import site.metacoding.white.domain.User;
import site.metacoding.white.domain.UserRepository;
import site.metacoding.white.dto.ResponseDto;
import site.metacoding.white.dto.SessionUser;
import site.metacoding.white.dto.UserReqDto.LoginReqDto;
import site.metacoding.white.util.SHA256;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements Filter {

    private final UserRepository userRepository; // DI 받음(FilterConfig에서 주입받음)

    // /login 요청시
    // post 요청시
    // username, password (json)
    // db확인
    // 토큰생성
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response; // 다운캐스팅 해야 쓸 수 있다

        // POST 요청이 아닌것을 거부
        if (!req.getMethod().equals("POST")) {
            customResponse("로그인시에는 POST 요청을 해야 합니다.", resp);
            return; // 스프링의 도움을 받을 수 없어서 직접 응답해줌 -> 필터는 DS 앞에서 동작
        }

        // Body값 받기 (request안에 존재)
        ObjectMapper om = new ObjectMapper();
        LoginReqDto loginReqDto = om.readValue(req.getInputStream(), LoginReqDto.class);
        log.debug("디버그 : " + loginReqDto.getUsername());
        log.debug("디버그 : " + loginReqDto.getPassword());

        // username이 존재하는지 체크
        Optional<User> userOP = userRepository.findByUsername(loginReqDto.getUsername());
        if (userOP.isEmpty()) {

            // findByUsername 나중에 처리하기
            customResponse("유저네임이 존재하지 않습니다.", resp);
            return;
        } // if-else는 가독성이 좀 떨어져서... 메서드로 최대한 빼는게 좋다

        // pw 체크
        User userPS = userOP.get();
        SHA256 sh = new SHA256();
        String encPassword = sh.encrypt(loginReqDto.getPassword());
        if (!userPS.getPassword().equals(encPassword)) {
            customResponse("패스워드가 틀렸습니다.", resp);
            return;
        }

        // JWT 토큰 생성 1ms = 1/1000초
        Date expire = new Date(System.currentTimeMillis() + (1000 * 60 * 60));

        String jwtToken = JWT.create()
                .withSubject("메타코딩") // 토큰 이름
                .withExpiresAt(expire) // 만료시간 -> 현재시간+x시간 이런식으로 써야함
                .withClaim("id", userPS.getId())
                .withClaim("username", userPS.getUsername()) // body, claim을 계속 연결해서 쓸 수 있다
                .sign(Algorithm.HMAC512("뺑소니")); // 사용 알고리즘
        log.debug("디버그 : " + jwtToken);

        // JWT 토큰 응답
        customJwtResponse(jwtToken, userPS, resp);

        // chain.doFilter(request, response);
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

    private void customJwtResponse(String token, User userPS, HttpServletResponse resp)
            throws IOException, JsonProcessingException {
        resp.setContentType("application/json; charset=utf-8");
        resp.setHeader("Authorization", "Bearer " + token); // 브라우저에 있는 키값으로 사용 -> 오타나면안된다...
        PrintWriter out = resp.getWriter(); // buffered write의 편한버전
        resp.setStatus(200);
        ResponseDto<?> responseDto = new ResponseDto<>(1, "로그인 성공", new SessionUser(userPS));
        ObjectMapper om = new ObjectMapper();
        String body = om.writeValueAsString(responseDto);
        out.println(body);
        out.flush();
    }

}
