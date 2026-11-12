# 데이터 안내

## 출처

- **PhiUSIIL Phishing URL (Website)**, UCI Machine Learning Repository
- https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
- 저자: Arvind Prasad, Shalini Chandra
- 원본: 정상 URL 134,850건, 피싱 URL 100,945건
- 원본 라벨: `1 = legitimate`, `0 = phishing`
- 라이선스: Creative Commons Attribution 4.0 International (CC BY 4.0)
- 인용: Prasad, A. & Chandra, S. (2024). *PhiUSIIL Phishing URL (Website)* [Dataset]. UCI Machine Learning Repository. https://doi.org/10.1016/j.cose.2023.103545

## 다운로드와 학습

프로젝트 폴더에서 의존성을 설치한 가상환경의 Python으로 실행합니다.

```powershell
.\.venv\Scripts\python.exe -m scripts.download_data
.\.venv\Scripts\python.exe -m scripts.train
```

macOS/Linux에서는 `.venv/bin/python`을 사용합니다. 다운로드는 공식 UCI 데이터 제공처에서만 수행하며 데이터에 포함된 URL의 웹페이지를 방문하지 않습니다.

다운로드 스크립트의 `--output-dir`로 저장 폴더를 지정할 수 있고, 기존 파일을 다시 내려받으려면 `--force`를 사용합니다. 학습 CLI는 다음 옵션을 제공합니다.

| 옵션 | 의미 |
| --- | --- |
| `--csv PATH` | 사용할 원본 CSV 경로 |
| `--output-dir DIR` | 모델과 평가 JSON 저장 폴더 |
| `--report PATH` | 모델 보고서 Markdown 경로 |
| `--seed 42` | 재현을 위한 난수 시드 |
| `--trees 80` | 랜덤 포레스트 트리 수 |
| `--max-depth 10` | 랜덤 포레스트 최대 깊이 |
| `--jobs 2` | 학습 병렬 작업 수 |
| `--vocabulary-size 30000` | 문자 TF-IDF 모델의 최대 문자 조합 수 |

원본·가공 데이터는 Git에서 제외합니다. 저장소의 `artifacts/`에는 앱 실행에 필요한 JSON 모델과 집계된 평가 결과가 포함됩니다.

## 처리와 평가 원칙

1. 원본 URL과 정답 라벨을 읽습니다.
2. 잘못된 형식, 중복 및 충돌 라벨을 점검합니다.
3. 등록 가능 도메인의 문자열에서 숫자 특징과 문자 2~5글자 TF-IDF를 추출합니다. 문자 어휘와 IDF는 학습 분할에서만 학습합니다. 정상 URL의 형식 수집 편향 때문에 HTTP/HTTPS, www, 경로·쿼리 등의 형식을 모델 입력에서 제외합니다. 원본 웹페이지 기반 특징도 사용하지 않습니다.
4. 피싱을 양성 클래스로 변환합니다. 원본 라벨 0이 피싱임에 유의합니다.
5. 등록 가능 도메인이 학습·검증·최종 평가 간 겹치지 않도록 나눕니다.
6. 각 실행에서는 검증 데이터로 모델과 임계값을 선택하고 별도 평가 분할에서 측정합니다. 개발 중 특징을 수정하며 같은 평가 분할을 재사용한 이력은 모델 보고서에 공개합니다.
7. 데이터 해시, 제외 건수, 분할 감사, 실제 측정값을 아티팩트와 모델 보고서에 기록합니다.

모델 점수는 피해 확률이 아니며, 과거 공개 데이터의 성능은 현재 모든 URL의 성능을 보장하지 않습니다. 실제 사용자 문자나 인증 토큰이 포함된 주소를 학습 데이터에 추가하지 않습니다.
