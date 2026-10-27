# [Web] simple_sqli

| 항목 | 내용 |
| --- | --- |
| 플랫폼 | Dreamhack 워게임 |
| 문제 URL | https://dreamhack.io/wargame/challenges/24 |
| 분야 | Web |
| 난이도 | Level 1 |
| 풀이 날짜 | 2026-10-27 |
| 소요 시간 | 5min |
| 핵심 키워드 | SQL Injection, 인증 우회 |
| CWE | CWE-89 (Improper Neutralization of Special Elements in SQL Command) |

## 1. 문제 개요
로그인 시 `userid`/`userpass` 입력값을 SQL 쿼리에 문자열로 직접 결합하는 Flask + SQLite 앱.
admin 계정으로 로그인에 성공하면 플래그가 노출된다.

## 2. 정찰(Recon)
제공된 소스에서 쿼리 생성부를 확인했다.

```python
query = f"SELECT * FROM users WHERE userid='{userid}' AND userpass='{userpass}'"
cur.execute(query)
```

- 사용자 입력이 파라미터 바인딩 없이 쿼리 문자열에 그대로 삽입됨.
- 따옴표 종류(`'` 인지 `"` 인지)를 소스에서 먼저 확인해야 페이로드가 쿼리 문법을 정확히 깨뜨릴 수 있다.

## 3. 취약점 분석
- 사용자 입력이 쿼리의 "데이터"가 아니라 "쿼리 구문의 일부"로 해석될 수 있음 → 입력으로 쿼리 구조(조건문) 자체를 바꿀 수 있다.
- 공격 조건: 로그인 폼 하나만 있으면 되고, 별도 인증이나 네트워크 위치 제약이 없어 난이도가 낮다. 영향은 인증 우회 전체.
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection').

## 4. 시도와 실패
| 시도 | 결과 | 배운 점 |
| --- | --- | --- |
| admin / admin 입력 | 실패 | 비밀번호를 모르므로 정상 경로로는 통과 불가 |
| 임의 특수문자 없이 긴 문자열 입력 | 실패(의미 없는 로그인 실패) | 쿼리 구조를 깨지 않으면 단순 입력 길이는 영향 없음 |
| '#'을 이용하여 주석처리 | 실패(500 error) | #은 mysql에서만 사용하는 주석 기호로써 공격 대상의 데이터베이스 langauge가 중요 |

## 5. 익스플로잇
1. 소스에서 확인한 따옴표(`'`)에 맞춰, `userid` 필드에 주석 처리형 페이로드를 입력해 비밀번호 비교 조건을 무력화한다.
2. 쿼리가 `WHERE userid='<입력>' AND userpass='<입력>'` 형태이므로, `userid`에 닫는 따옴표 + 주석 기호를 넣으면 뒤의 `AND userpass=...` 조건이 통째로 주석 처리된다.
3. 결과적으로 `userid` 조건만 만족하는 계정(`admin`)으로 로그인된다. (userid : admin" --, userpass : 1234(무작위))
4. 로그인 성공 후 반환되는 페이지/세션에서 플래그를 확인한다.

## 6. 방어 관점
- **근본 대책**: Prepared Statement(파라미터 바인딩)로 입력과 쿼리 구조를 분리한다. 입력이 어떤 값이어도 "데이터"로만 취급된다.
  ```python
  # 기존(취약) — 문자열 결자
  query = f"SELECT * FROM users WHERE userid='{userid}' AND userpass='{userpass}'"
  cur.execute(query)

  # 개선 — 파라미터 바인딩
  cur.execute(
      "SELECT * FROM users WHERE userid = ? AND userpass = ?",
      (userid, userpass)
  )
  ```
- **보완 대책**:
  - 입력 길이·허용 문자 검증(화이트리스트)으로 2차 방어선을 둔다.
  - DB 계정에 최소 권한만 부여해, 주입이 뚫려도 피해 범위를 제한한다.
  - 에러 메시지에 쿼리/스택트레이스를 노출하지 않는다(정보 노출로 공격 난이도가 낮아짐).

## 7. 탐지 관점
- 로그인 파라미터 값에 SQL 메타문자(`'`, `--`, `;`, `union`, `or 1=1` 등)가 포함된 요청은 탐지 대상으로 본다.
- Sigma 스타일 초안:
  ```yaml
  title: 로그인 파라미터 SQL Injection 의심 패턴
  logsource:
    category: webserver
  detection:
    selection:
      http.method: 'POST'
      http.path: '/login'
      http.body|re: "('|--|;|\\bunion\\b|\\bor\\s+1=1\\b)"
    condition: selection
  level: medium
  ```
- 오탐 완화: 아포스트로피가 들어가는 정상 입력(예: 이름에 `O'Brien`)이 있을 수 있으므로, 단일 조건 탐지보다 반복 실패 로그인 횟수·응답 시간 편차와 함께 상관분석하는 것이 정확도를 높인다.
