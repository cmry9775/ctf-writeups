# [Web] pathtraversal

| 항목 | 내용 |
| --- | --- |
| 플랫폼 | Dreamhack 워게임 |
| 문제 URL | https://dreamhack.io/wargame/challenges/12 |
| 분야 | Web |
| 난이도 | B4 |
| 풀이 날짜 | 2026-11-2 |
| 소요 시간 | 30min |
| 핵심 키워드 | Path Traversal,  |
| CWE |  |

## 1. 문제 개요


## 2. 정찰(Recon)
제공된 소스(`app.py`)에서 업로드·조회 로직을 확인했습니다.



## 3. 취약점 분석


## 4. 시도와 실패
| 시도 | 결과 | 배운 점 |
| --- | --- | --- |
| `?name=flag.py` 입력 (트래버설 없이) | 실패 (`flag.py does not exist :(`) | `read_memo()`는 `uploads/` 기준 상대경로이므로, 그 디렉터리 안에 없는 파일은 경로를 더 조작해야 접근 가능 |
| `/upload`에서 `filename=../x` 업로드 시도 | 실패 (`bad characters,,`) | 업로드 쪽은 `..` 필터가 동작 — 조회로 디렉터리를 탈출해서 읽기 |

## 5. 익스플로잇
1. upload를 이용하여 임의의 데이터를 업로드합니다.

![alt text](image.png)

2. URL의 파라미터를 `name=hello`에서 `name=../flag.py`로 변경합니다.
3. 서버가 `uploads/../flag.py`를 열어 그 내용을 그대로 화면에 출력 — `FLAG = "..."` 전체가 노출됩니다.

## 6. 방어 관점
- **근본 대책**: 사용자가 지정한 파일명을 경로의 일부로 직접 쓰지 않는 것입니니. 업로드 시 서버가 임의의 안전한 식별자(UUID 등)를 생성해 실제 저장 경로로 쓰고, 사용자가 준 파일명은 표시용으로로로 보관합니다.
  ```python
  # 기존(취약) — 사용자 입력을 경로에 직접 결합
  with open(f'{UPLOAD_DIR}/{filename}', 'wb') as f:
      f.write(content)

  # 개선 — 경로 정규화 후 허용 디렉터리를 벗어나는지 검증
  import os
  safe_path = os.path.normpath(os.path.join(UPLOAD_DIR, filename))
  if not safe_path.startswith(os.path.abspath(UPLOAD_DIR)):
      abort(400)
  ```
- **보완 대책**: 업로드·조회 등 **같은 자원에 접근하는 모든 엔드포인트에 동일한 검증 로직을 공유**해서, 한쪽만 막고 다른 쪽은 빠뜨리는 비일관성 자체를 구조적으로 없애야 합니다. 추가로 `flag.py` 같은 민감 파일을 애플리케이션 루트(조회 가능한 디렉터리의 바로 상위)에 두지 않고, 웹 루트 바깥의 별도 경로나 환경변수로 분리합니다.

## 7. 탐지 관점
- 웹 로그에서 `name`/`file`/`filename` 류 파라미터 값에 `../`, 인코딩된 변형(`%2e%2e%2f`, `..%2f`, `....//`) 등 경로 조작 패턴이 포함된 요청을 탐지 대상으로 삼습니다.
- Sigma 스타일 초안:
  ```yaml
  title: Path Traversal 의심 - 파일 조회 파라미터에 상위 경로 이동 패턴
  logsource:
    category: webserver
  detection:
    selection:
      http.method: 'GET'
      http.path: '/read'
      http.query|re: "(\\.\\.(/|%2e%2e|%2f))"
    condition: selection
  level: high
  ```
- 오탐 완화: 정상적인 조회 파라미터에는 경로 구분자가 들어갈 일이 거의 없으므로 오탐률 자체는 낮은 편입니다.
