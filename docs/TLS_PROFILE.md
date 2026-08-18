# Magnus TLS Profile 결정

TLS는 코어에 섞지 않고 transport interface로 분리한다. 평문과 TLS 연결이 같은 HTTP
parser와 phase engine을 공유하고 `read`, `write`, `sendfile` 동작만 transport가 선택한다.

초기 TLS profile은 OpenSSL 3.x 공개 API를 사용하며 TLS 1.2/1.3만 허용한다. 기본값은
TLS 1.3, 안전한 cipher suite, session ticket key rotation, OCSP stapling이다. OpenSSL의
Apache-2.0 라이선스와 배포 고지를 보존한다.

TLS에서는 커널 `sendfile`을 직접 사용할 수 없으므로 bounded buffer 또는 kTLS를
선택한다. kTLS는 최적화이며 필수 조건이 아니다. 인증서는 시작할 때 모두 검증하고,
추후 `magnusd`가 검증된 새 context를 원자적으로 전달한다.

완료 조건은 잘못된 handshake corpus, TLS version/cipher 검사, 인증서 교체 중 연결 유지,
평문 대비 처리량·메모리·이미지 크기의 공개다.
