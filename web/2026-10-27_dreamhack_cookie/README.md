# [Web] cookie

| 항목 | 내용 |
| --- | --- |
| 플랫폼 | Dreamhack 워게임 |
| 문제 URL | https://dreamhack.io/wargame/challenges/6 |
| 분야 | Web |
| 난이도 | Level 1 |
| 풀이 날짜 | 2026-10-27 |
| 소요 시간 | __ |
| 핵심 키워드 | 쿠키 변조, 인증 우회 |
| CWE | CWE-565 (Reliance on Cookies without Validation) |

## 1. 문제 개요
로그인 기능이 있는 Flask 앱. 로그인하면 쿠키에 `username`이 평문으로 저장되고,
`/admin` 라우트는 요청 쿠키의 `username` 값이 `admin`이면 별도 인증 없이 플래그를 반환한다.
admin 계정의 비밀번호 자체가 플래그이므로, 정상 로그인 경로로는 `/admin`에 도달할 수 없다.

## 2. 정찰(Recon)
제공된 소스에서 두 지점을 확인했다.

```python
# /login
resp = make_response(redirect('/'))
resp.set_cookie('username', username)   # 서버 서명·암호화 없이 그대로 저장
return resp

# /admin
if request.cookies.get('username') == 'admin':
    return FLAG
return '권한 없음'
```

- 쿠키가 `itsdangerous`/`session` 서명 없이 `set_cookie`로 바로 내려감 → 클라이언트가 값을 그대로 바꿀 수 있음.
- 브라우저 개발자도구(Application → Cookies) 또는 Burp Suite로 `username` 쿠키 값을 확인·수정 가능함을 확인.

## 3. 취약점 분석
- 서버가 "인증되었다"는 상태를 전적으로 클라이언트가 보낸 쿠키 값에 의존하고, 그 값의 무결성을 검증하지 않음.
- 공격 조건: 쿠키 편집 권한(브라우저 자체 기능)만 있으면 되므로 난이도가 매우 낮고, 영향은 관리자 권한 전체 탈취로 범위가 크다.
- CWE-565: Reliance on Cookies without Validation and Integrity Checking.
- 참고로 CWE-287(Improper Authentication)의 하위 사례로도 분류 가능.

## 4. 시도와 실패
| 시도 | 결과 | 배운 점 |
| --- | --- | --- |
| admin / admin 으로 로그인 | 실패 | admin 비밀번호 = 플래그 값이라 추측 불가, 로그인 경로는 의도적으로 막혀 있음 |
| `/admin` 비로그인 상태로 직접 접근 | 실패("권한 없음") | 쿠키 자체가 없으면 비교에서 걸림 → 먼저 쿠키를 "존재"시켜야 함 |

## 5. 익스플로잇
1. 아무 계정(`guest`/`guest` 등)으로 정상 로그인 → 응답 쿠키에 `username=guest`가 설정됨을 확인.
2. 브라우저 개발자도구의 Application → Cookies (또는 Burp Suite의 Proxy/Repeater)에서 `username` 쿠키 값을 `admin`으로 수정.
3. 수정된 쿠키를 유지한 채 `/admin`에 재요청.
4. 서버가 쿠키 값만 비교하므로 플래그가 그대로 반환. 

## 6. 방어 관점
- **근본 대책**: 인증 상태는 서버 측 세션 저장소에만 두고, 클라이언트에는 위조 불가능한 세션 ID만 전달한다. Flask라면 서명된 `session` 객체를 쓴다.
  ```python
  # 기존(취약)
  resp.set_cookie('username', username)

  # 개선 — 서명된 세션에 "누구인지"가 아니라 "세션 ID"만 저장하고,
  # 권한 판단은 서버가 세션 ID로 DB/캐시를 조회해서 수행
  session['user_id'] = user.id
  ```
- **보완 대책**:
  - 쿠키에 `HttpOnly`, `Secure`, `SameSite=Lax/Strict` 속성을 설정해 탈취·전송 경로를 줄인다.
  - 역할/권한 값을 쿠키·클라이언트 전달 토큰에 평문으로 담지 않는다. 불가피하면 HMAC 서명으로 무결성을 검증한다.
  - 세션 고정(session fixation), 로그아웃 시 세션 무효화 등 세션 관리 정책을 함께 점검한다.

## 7. 탐지 관점
- 로그 기준: 특정 세션/IP에서 **로그인 성공 이력 없이** `/admin` 응답이 200(또는 플래그 응답)인 경우는 비정상이다.
- Sigma 스타일 초안:
  ```yaml
  title: 쿠키 기반 권한 상승 의심 (admin 쿠키, 로그인 이력 없음)
  logsource:
    category: webserver
  detection:
    selection:
      http.path: '/admin'
      http.cookie|contains: 'username=admin'
    filter:
      session_id|in_prior_login_log: true
    condition: selection and not filter
  level: high
  ```
- 오탐 완화: 실제 admin 계정이 정상 로그인 후 접근하는 경우를 `filter`로 제외해야 한다. 세션 ID와 로그인 로그를 함께 봐야 정확도가 올라간다.