# Magnus Enterprise Architecture

## 제품 원칙

Magnus의 목표는 기능 수를 무작정 늘리는 것이 아니라, data plane을 작고 예측 가능하게
유지하면서 엔터프라이즈 운영 기능을 별도 control plane으로 분리하는 것이다. 요청을
처리하는 `magnus`는 C17 단일 바이너리, `magnusd`는 무거운 관리 작업을 담당한다.

## 핵심 설계 개념

Magnus는 아래 운영 개념을 독립적으로 설계·구현한다.

- 비동기 event loop와 연결당 최소 비용의 `magnus_reactor`, bounded connection arena,
  무중단 generation worker 교체
- typed phase API와 조합 가능한 request/response filter chain
- 정적·동적 업무를 분리하는 service group과 `magnus_service` 기반 장애 격리
- `magnusd`가 관리하는 upstream cluster health, load balancing, session affinity,
  원자적 generation 배포/rollback

## 구성 경계

```text
Client
  │
  ▼
magnus data plane
  reactor → protocol parser → ingress → route → service → response → log
                                  │          │
                                  │          └─ static / proxy / app connector
                                  └─ policy, admission, auth, rate limit
  ▲
  │ versioned config over a local authenticated channel
  ▼
magnusd control plane
  config validation · certificates · discovery · health · deploy · rollback · audit
```

data plane은 요청 경로에서 파일 I/O와 동적 할당을 최소화한다. 설정은 불변 snapshot으로
컴파일한 뒤 generation 단위로 교체하며, 기존 연결은 이전 generation에서 배출한다.

## 개발 순서

1.0.0까지 실제로 구현·검증된 범위와 그 이후 순서는 `docs/ROADMAP.md`에 정리한다.

## 엔터프라이즈 완료 기준

- malformed HTTP corpus와 parser fuzzing에서 crash 및 OOB 0건
- 부하 중 config/certificate 교체 시 연결 손실 기준을 수치로 정의하고 충족
- upstream 장애·지연·부분 장애에 retry storm이 발생하지 않음
- worker crash 격리와 자동 복구, 설정 rollback, 변경 감사 추적
- Prometheus/OpenTelemetry 호환 관측성과 요청 단위 correlation
- 재현 가능한 build, SBOM, 서명 이미지, 취약점 대응 정책

## Phase Engine SDK

Phase Engine 0.1은 ingress, response, log 세 지점을 연결한다. handler 등록에는
phase, priority, name과 함수 포인터가 필요하다. 낮은 priority가 먼저 실행된다.
내장 trace hook은 request ID를 생성하며, upstream이 같은 이름의 header를 보내도
제거한 뒤 Magnus가 생성한 값으로 교체한다.

다음 구현 순서는 admission control, active health state, cache policy, identity,
routing, audit다. 기능별 모듈은 이 Phase Engine SDK에 handler를 등록하는 방식으로만
확장하며, data plane 코어를 직접 수정하지 않는다.

원칙:

- blocking file/network I/O를 request hook에서 실행하지 않는다.
- third-party 코드를 도입하면 파일 단위 저작권과 NOTICE를 보존한다.
- 모든 확장은 phase, priority, name 단위로 등록·추적한다.

## 크기 예산

1.0.0 data-plane 이미지는 9,207,512 bytes(약 8.78MiB)다. 관리 console과 control
plane은 data-plane 이미지에 넣지 않는다. 크기보다 메모리 상한, tail latency, 안전성을
우선하며 각 profile의 기능과 크기를 함께 공개한다.
