# Nyeon-Auth

**목적**
* 반복적인 소셜 로그인 기능 구현 대체
* OAuth 2.1 프로토콜을 준수하여 SPA 환경(Public Client)의 인증/인가 [Best Practice](https://curity.io/resources/learn/spa-best-practices/) 적용
* 정해진 클라이언트만 리소스에 접근할 수 있도록 제한

**기능**
* 소셜 로그인을 통한 Resource Owner 인증
  * 지원 목록
    * 구글
    * Github
* Authorization Code Grant With PKCE
  * Authorization Code 탈취 공격 방지
* OIDC 지원-id 토큰으로 api 호출 없이 사용자 정보 제공
* [Protocol Endpoint](https://docs.spring.io/spring-authorization-server/reference/protocol-endpoints.html)

**기술 스택**
* Java 17
* Spring Boot 3.2.5
* Spring Security 6.2.4
* Spring Authorization Server 1.2.4
