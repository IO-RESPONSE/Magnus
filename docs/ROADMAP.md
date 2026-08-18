# Roadmap

## M0 — Foundation

- 명칭, 디렉터리, 라이선스와 upstream 추적 정책
- 재현 가능한 x86_64 빌드
- 최소 보안 설정과 컨테이너 health check
- 설정 검사 및 reload 스크립트

## M1 — Operations

- Magnus Phase Engine SDK: ingress/response/log hook와 priority
- 요청 ID와 신뢰 가능한 phase trace header
- `magnusd` 로컬 관리 API
- `magnusctl validate`, `apply`, `status`, `rollback`
- Prometheus metrics와 JSON 상태 API
- 웹 대시보드 읽기 전용 화면
- 0.2 운영 프로파일의 60초 P1/P2/T1 정식 반복시험
- 동시성 1024에서 S1 처리량 회귀 원인 분석

## M2 — Traffic intelligence

- HTTP/TCP Active Health Check
- 동적 upstream 관리
- cookie 기반 session persistence
- latency 및 inflight 기반 load balancing
- overload admission control과 bounded queue
- stale-while-revalidate response cache 운영 프로파일
- backend 장애 중 cache-stale 가용성 비교 시나리오

## M3 — Enterprise control

- 사용자, 역할과 권한 정책
- OIDC/JWT 및 mTLS
- 감사 로그와 변경 승인
- 인증서 수명주기와 안전한 secret provider 연동

## M4 — High availability

- 다중 노드 설정 배포와 상태 수렴
- leader 장애 시 제어 영역 복구
- canary 반영, 자동 rollback, 백업과 복원

## M5 — Release validation

- 정적 응답과 reverse proxy 시나리오 분리 성능 회귀 시험
- throughput, latency p50/p95/p99/p99.9, 오류율, CPU와 RSS 기록
- Linux 7.1 이상 전용 호스트에서 최종 결과 재현
