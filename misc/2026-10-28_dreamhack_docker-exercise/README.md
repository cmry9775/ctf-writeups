# [Misc] Exercise: Docker

| 항목 | 내용 |
| --- | --- |
| 플랫폼 | Dreamhack 워게임 (Dreamhack 강의 "Exercise: Docker" 연계) |
| 문제 URL | https://dreamhack.io/wargame/challenges/876/ |
| 분야 | Misc (Docker 실습) |
| 난이도 | 실습(Tutorial) — 플래그 획득이 목적이 아니라 Docker 빌드·실행 워크플로우 체득이 목적 |
| 풀이 날짜 | 2026-10-28 |
| 소요 시간 | 1min |
| 핵심 키워드 | Docker build/run, 이미지·컨테이너 생명주기, Dockerfile 구조 분석 |
| CWE | 해당 없음 |

## 1. 문제 개요
이 문제는 다른 워게임 문제들과 달리 **취약점을 찾아 플래그를 획득하는 것이 목표가 아니다.** Dockerfile로 이미지를 직접 빌드하고, 그 이미지로 컨테이너를 실행해 문제 환경에 접속하는 **Docker 기본 워크플로우를 실습**하는 것이 목적입니다.

제공 파일을 받으면 `Dockerfile`과 `deploy`(배포용 구성)가 들어 있습니다. 컨테이너 내부에는 `chall`(실행 시 `Hello Beginners!` 출력)과 `flag` 파일이 있으며, `cat flag`로 곧바로 플래그를 확인할 수 있다 — 즉 "탈취"가 아니라 "컨테이너 접속 자체"가 과제입니다.

## 2. 환경 구성 확인
- 제공된 폴더 전체를 리눅스 VM으로 옮긴 뒤, `Dockerfile`이 있는 디렉토리에서 작업합니다.
- 폴더 구성:
  ```
  ./
  ├── Dockerfile
  └── deploy/      # 컨테이너에 COPY될 실습용 바이너리(chall)·flag 등
  ```
- `Dockerfile`은 베이스 이미지 선택, `chall`/`flag` 파일을 이미지에 `COPY`하는 지시어, 컨테이너 시작 시 동작(`CMD`/`ENTRYPOINT`)으로 구성된 전형적인 "문제 환경 패키징용" Dockerfile이입니다.

## 3. 핵심 개념 정리 — 이미지와 컨테이너의 관계
CTF 환경에서 Docker를 쓰는 이유와 명령어별 역할을 정리하면 다음과 같습니다.

| 명령 | 역할 |
| --- | --- |
| `docker build .` | 현재 디렉토리의 `Dockerfile`을 읽어 **이미지(immutable 템플릿)** 를 생성. 레이어 단위로 캐시되어 재빌드 시 변경된 레이어만 다시 빌드 |
| `docker images` | 빌드된 이미지 목록과 이미지 ID 확인 |
| `docker run -it <IMAGE_ID> /bin/bash` | 이미지로부터 **새 컨테이너(실행 인스턴스)** 를 생성하고 즉시 bash 셸을 연결 |
| `docker ps` / `docker ps -a` | 실행 중인 컨테이너만 / 종료된 컨테이너까지 전체 목록 확인 |
| `docker start <ID>` + `docker exec -it <ID> bash` | **이미 만들어진(종료된) 컨테이너**를 재시작하고 그 안으로 재접속 — `run`과 달리 새 컨테이너를 만들지 않고 기존 컨테이너의 상태(파일 변경 등)를 그대로 유지 |

`run`을 반복 실행하면 매번 새 컨테이너가 생성되어 `docker ps -a`에 계속 쌓이고, 이전 컨테이너에서 설치한 디버깅 도구 등은 사라집니니. 반대로 `start`/`exec`로 같은 컨테이너에 재접속하면 이전 작업 상태(설치한 패키지, 생성한 파일)가 유지됩니다.

## 4. 진행 절차와 확인 포인트
| 단계 | 내용 | 배운 점 |
| --- | --- | --- |
| 이미지 빌드 | `docker build .` 실행 후 `docker images`로 생성된 이미지 ID 확인 | 빌드 시점마다 새 이미지가 생기므로, 태그(`-t`)를 지정하지 않으면 ID로만 구분해야 함 — 실무에서는 `docker build -t <name>:<tag> .`로 태깅하는 습관이 필요 |
| 컨테이너 실행 | `docker run -it <IMAGE_ID> /bin/bash`로 접속 | `ls`로 `chall`·`flag` 확인 → `./chall` 실행 시 `Hello Beginners!` 출력 → `cat flag`로 플래그 확인 |
| 도구 설치 | 컨테이너 내부에서 디버거 등 추가 설치 가능 | 설치한 도구는 **해당 컨테이너에만** 유지되며, 이미지 자체는 변경되지 않음(컨테이너를 커밋하지 않는 한) |
| 컨테이너 종료 후 재확인 | `exit`로 나온 뒤 `docker ps -a` | 종료된 컨테이너도 사라지지 않고 목록에 남아 있음을 확인 |
| 컨테이너 재접속 | `docker start <ID>` → `docker exec -it <ID> bash` | 새 컨테이너를 만들지 않고 기존 컨테이너 상태 그대로 재진입 가능함을 확인 |

## 5. 실습 절차 (요약)
1. 문제 파일(`Dockerfile`, `deploy/`)을 리눅스 VM으로 복사.
2. `Dockerfile`이 있는 디렉토리에서 이미지 빌드:
   ```bash
   docker build .
   docker images   # 생성된 이미지 ID 확인 (예: 08a83756c396)
   ```
3. 빌드된 이미지로 컨테이너를 생성·실행하며 bash 셸 진입:
   ```bash
   docker run -it 08a83756c396 /bin/bash
   ```
4. 컨테이너 내부에서 플래그 확인:
   ```bash
   ls           # chall, flag 확인
   ./chall      # Hello Beginners! 출력
   cat flag     # 플래그 출력
   ```
5. 컨테이너를 나온 뒤 목록·재접속 동작 확인:
   ```bash
   exit
   docker ps -a                       # 종료된 컨테이너도 조회됨
   docker start <CONTAINER_ID>
   docker exec -it <CONTAINER_ID> bash
   ```

## 6. 보안/실무 관점 — Dockerfile을 "공격자 시선"으로 다시 보기
이 실습 자체는 취약점이 없지만, **실제 운영 환경의 Dockerfile을 점검할 때는 아래 관점을 함께 봐야 합니다.**

- **민감정보를 이미지 레이어에 넣지 않기**: 이 문제처럼 `flag`를 `COPY`로 이미지에 박아 넣는 구조는 실습·CTF용으로는 적절하지만, 운영 환경에서 API 키·비밀번호를 `COPY`나 `ENV`로 이미지에 포함시키면 `docker history`나 이미지 레이어 추출만으로 평문 노출됩니다. 시크릿은 `--secret`(BuildKit) 또는 런타임 환경변수/시크릿 매니저로 주입해야 합니다.
- **non-root 사용자로 실행**: `USER` 지시어 없이 기본 root로 실행되는 컨테이너는, 컨테이너 탈출(escape) 취약점이 발생했을 때 호스트 권한 상승으로 바로 이어질 수 있습니니. 실습용 이미지와 달리 운영 이미지는 반드시 `USER` 지정이 필요합니다.

## 7. 운영 관점 — 컨테이너 생명주기 명령의 보안적 의미
- `docker ps -a`로 **종료된 컨테이너까지 전부 남아있다**는 점은, 실습에선 편리하지만 운영 환경에서는 **디버깅 흔적(설치 도구, 임시 파일)이 담긴 컨테이너가 정리되지 않고 누적**될 수 있다는 뜻입니다.
- `docker exec`로 실행 중인 컨테이너에 자유롭게 진입할 수 있다는 것은, **호스트의 Docker 소켓(`/var/run/docker.sock`)에 접근 권한이 있는 사용자/프로세스는 사실상 모든 컨테이너를 제어할 수 있다**는 의미이기도 합니다. CI/CD 파이프라인이나 웹 애플리케이션 컨테이너에 Docker 소켓을 무심코 마운트(`-v /var/run/docker.sock:/var/run/docker.sock`)하면, 컨테이너 침해가 곧 호스트 전체 장악으로 이어지는 잘 알려진 컨테이너 탈출 경로가 됩니다.
