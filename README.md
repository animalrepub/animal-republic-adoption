# 애니멀공화국 입양센터 — 서버 연동 버전

V7 화면 구성을 바탕으로, 모든 직원이 **하나의 공통 비밀번호**를 사용하고 변경 즉시 모든 기기에 반영되도록 구성한 Flask/SQLite 웹앱입니다.

## 시작하기

Python 3.10+ 설치 후 프로젝트 폴더에서:

```bash
python -m pip install -r requirements.txt
```

환경변수 2개를 설정합니다. **비밀번호는 코드나 GitHub에 올리지 마세요.**

macOS/Linux:
```bash
export APP_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export INITIAL_ADMIN_PASSWORD='최초_관리자_비밀번호_12자_이상'
export COOKIE_SECURE=0  # 로컬 http 테스트에만 사용
python app.py
```

Windows PowerShell:
```powershell
$env:APP_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
$env:INITIAL_ADMIN_PASSWORD = '최초_관리자_비밀번호_12자_이상'
$env:COOKIE_SECURE = '0'  # 로컬 http 테스트에만 사용
python app.py
```

브라우저에서 `http://127.0.0.1:5000` 접속. **HTML 파일을 더블클릭하는 방식으로는 작동하지 않습니다.**

## 비밀번호 변경과 공유

관리자 → 공통 비밀번호 변경 → 현재 비밀번호와 새 비밀번호 입력 → 저장.

- 비밀번호는 서버의 SQLite DB에 해시로 보관됩니다.
- 변경하면 서버의 `password_version`이 증가합니다.
- 모든 기존 관리자 세션은 다음 API 요청부터 거부되며 새 비밀번호로 다시 진입해야 합니다.
- 다른 기기에서도 같은 서버 주소에 접속하면 새 비밀번호를 사용합니다.
- 관리자 계정/이메일은 필요 없습니다.

## 배포 전 반드시 수행할 작업

1. HTTPS를 지원하는 서버에 배포하고 `COOKIE_SECURE=1` 유지. 여러 기기가 **같은 서버와 같은 DB**를 사용하도록 구성.
2. `APP_SECRET_KEY`는 고정된 긴 난수로 서버 비밀 설정에 저장. DB 파일은 외부 공개 디렉터리에 두지 말고 암호화된 백업 마련.
3. 개인정보 수집·이용 동의와 선택적 마케팅 동의를 분리하고, 개인정보 처리방침/보관 기간/파기 정책 확정. 현재 원본 설문 1번 문항은 그대로 남아 있어 **실제 고객 정보 수집 전 개정이 필수**입니다.
4. 비밀번호 무차별 대입 방어는 단일 프로세스 메모리 기반으로 기본 제공됩니다. 공개 운영에서는 프록시/IP 기준의 영구적·분산형 속도 제한과 접근 로그, 보안 점검 추가.
5. 관리자 공통 비밀번호는 사용자를 개별 식별하지 못합니다. 직원별 변경 이력이 필요하면 추후 개별 계정 방식으로 확장.
6. 상담 시간은 **희망 시간**이며 실제 예약 가능 시간표/중복 예약 방지/알림 전송은 아직 구현되지 않았습니다.
7. 고양이 사진은 서버 DB에 이미지 데이터로 저장하는 초기 방식입니다. 운영 규모가 커지면 별도 파일 스토리지로 이전 권장.

## 데이터 파일

최초 실행 시 `adoption.sqlite3`가 생성되며, 이후 재시작해도 데이터가 유지됩니다. 이 파일을 외부에 공유하지 마세요. 비밀번호를 변경해도 `INITIAL_ADMIN_PASSWORD`는 다시 적용되지 않습니다.
