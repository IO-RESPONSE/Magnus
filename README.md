# Magnus

Magnus는 IORESPONSE가 독립적으로 개발하는 **초경량 엔터프라이즈 Web/Application
Gateway**다.

## 현재 구현

- 외부 웹서버 런타임에 의존하지 않는 독립 C17/epoll 이벤트 코어
- 엄격한 HTTP/1.0·1.1 parser, keep-alive, 8KiB 요청 상한
- 안전한 document root, MIME/HEAD, zero-copy `sendfile` 정적 파일 전송
- 구조화된 요청 ID 기반 access log
- ingress → route → response → log 네이티브 phase API
- 요청별 128-bit 추적 ID, health endpoint, 명확한 오류 응답
- SIGTERM/SIGINT graceful shutdown
- RELRO/NOW, FORTIFY, 비루트 사용자, 읽기 전용 rootfs
- Micro Linux 기반 0.2-edge 이미지: 5,927,988 bytes (약 5.65 MiB)

현재 버전은 엔터프라이즈 제품의 M1a edge 코어다. TLS, reverse proxy, upstream cluster,
동적 설정 반영과 관리 plane은 아직 구현되지 않았으므로 현 단계를 production-ready라고
표현하지 않는다. 목표 구조와 완료 기준은 `docs/ENTERPRISE_ARCHITECTURE.md`에 있다.

## 제품 구성

- `magnus`: 독립 HTTP/event data plane
- `magnusd`: 설정 검증, 배포, 인증서, cluster 상태를 다룰 control plane(계획)
- `magnusctl`: 관리 CLI(계획)
- `Magnus Module ABI`: 단계별 native extension 인터페이스(초기 API 구현)

## 개발과 검증

```bash
./scripts/check.sh
make test
./scripts/build-image.sh
./scripts/test-image.sh
docker compose config
```

이전 초기 실험 코드는 `experiments/`에 격리했다. 기존 benchmark 결과는 역사적
기준선일 뿐 현재 네이티브 Magnus의 성능 결과가 아니다.

## 라이선스 경계

Magnus는 AI(Claude)의 지원을 받아 개발되었다. 사용은 자유롭게 허용하지만,
소스 코드와 바이너리에 대한 수정은 누구에게도 허용되지 않는다. 자세한 조건은
`LICENSE`를 따른다.
