# 데이터 안내

## 사용 예정 데이터

- 명칭: PhiUSIIL Phishing URL (Website)
- 제공: UCI Machine Learning Repository
- 출처: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
- 저자: Arvind Prasad, Shalini Chandra
- 정상 URL: 134,850건
- 피싱 URL: 100,945건
- 원본 라벨: `1 = 정상`, `0 = 피싱`
- 라이선스: CC BY 4.0
- 인용: Prasad, A. & Chandra, S. (2024). PhiUSIIL Phishing URL (Website) [Dataset]. UCI Machine Learning Repository. https://doi.org/10.1016/j.cose.2023.103545

## 데이터 준비 계획

1. 출처 페이지의 Download에서 압축 파일을 받습니다.
2. 압축을 해제한 원본 CSV를 로컬 `data/raw/`에 보관합니다.
3. URL과 라벨을 읽고 중복, 파싱 불가 주소, 클래스 분포를 확인합니다.
4. URL 문자열에서 특징을 직접 계산합니다.
5. 등록 가능 도메인 그룹을 기준으로 학습·검증·최종 평가 데이터를 분리합니다.

현재 저장소에는 원본 데이터, 가공 데이터, 학습 모델을 포함하지 않습니다. 다운로드 및 전처리 자동화 코드는 추후 추가합니다.

학습 URL의 웹페이지를 자동으로 방문하거나 링크를 클릭하지 않습니다. 실제 사용자 문자, 인증 토큰, 개인정보가 포함된 주소는 학습 데이터로 추가하지 않습니다.
