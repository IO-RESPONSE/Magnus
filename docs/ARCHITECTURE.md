# Architecture

```text
Operator / CI
     |
 magnusctl ------ Magnus Console
     |                 |
     +------ magnusd ---+
                |
       validate / render / reload
                |
         Magnus data plane
                |
       upstream applications
```

## Data plane

독립 C17/epoll 엔진으로 구성한다. 요청 처리는 관리 데몬과 분리하여 제어 영역
장애가 기존 트래픽 처리에 영향을 주지 않게 한다.

### Magnus Phase Engine

Magnus 모듈은 공통 SDK를 통해 ingress, response, log phase에 handler를 등록한다.
handler는 priority 순서로 실행되며 event loop 안에서 blocking I/O 없이 동작해야
한다.

```text
request → ingress hooks → route/content → response hooks → log hooks
```

첫 내장 hook은 32자리 request ID를 만들고 response에 engine과 phase 정보를
기록한다. 이후 admission, identity, cache, routing과 audit handler를 같은 chain에
추가한다.

## Control plane

`magnusd`는 선언형 설정을 받아 임시 파일에 렌더링하고 구문 검사 후 원자적으로
교체한다. 변경 이력, 작업자, 해시와 rollback 지점을 보존한다.

## 기본 보안 원칙

- non-root worker와 읽기 전용 root filesystem
- 관리 API와 트래픽 listener 분리
- Unix socket 우선, 원격 API는 mTLS 적용
- 비밀값은 설정 문서에 저장하지 않고 참조만 저장
- 모든 변경은 검증, 감사 기록, 원자적 반영 순서로 처리
- 모듈 ABI와 upstream 버전을 release manifest에 고정
