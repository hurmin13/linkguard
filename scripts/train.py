"""Reproducible grouped evaluation and portable model export for LinkGuard."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
import tldextract
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from linkguard.features import FEATURE_NAMES, FEATURE_VERSION, extract_features
from linkguard.model import predict_score
from linkguard.urltools import parse_url
from scripts.download_data import CSV_NAME, DATASET_PAGE, ROOT, download_dataset, sha256_file


def classification_metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    predicted = np.asarray(scores) >= threshold
    tn, fp, fn, tp = map(int, confusion_matrix(y_true, predicted, labels=[0, 1]).ravel())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "threshold": float(threshold), "precision": precision, "recall": recall, "f1": f1,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "accuracy": (tp + tn) / (tp + tn + fp + fn),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


def write_json(path: Path, value: object, *, compact: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=None if compact else 2,
                               separators=(",", ":") if compact else None, allow_nan=False) + "\n", encoding="utf-8")


def export_model(model, model_type: str, metadata: dict) -> dict:
    if model_type == "char_ngram_logistic":
        vectorizer, classifier = model.steps[0][1], model.steps[1][1]
        parameters = {
            "vocabulary": {key: int(value) for key, value in vectorizer.vocabulary_.items()},
            "idf": vectorizer.idf_.tolist(), "coef": classifier.coef_[0].tolist(),
            "intercept": float(classifier.intercept_[0]),
            "ngram_range": list(vectorizer.ngram_range), "sublinear_tf": vectorizer.sublinear_tf,
            "norm": vectorizer.norm, "lowercase": vectorizer.lowercase,
        }
    elif model_type == "logistic_regression":
        scaler, classifier = model.steps[0][1], model.steps[1][1]
        parameters = {
            "mean": scaler.mean_.tolist(), "scale": scaler.scale_.tolist(),
            "coef": classifier.coef_[0].tolist(), "intercept": float(classifier.intercept_[0]),
        }
    else:
        trees = []
        for estimator in model.estimators_:
            tree = estimator.tree_
            values = tree.value[:, 0, :]
            probabilities = values[:, 1] / values.sum(axis=1)
            trees.append({
                "left": tree.children_left.tolist(), "right": tree.children_right.tolist(),
                "feature": tree.feature.tolist(), "threshold": tree.threshold.tolist(),
                "phishing_probability": probabilities.tolist(),
            })
        parameters = {"trees": trees}
    return {"format_version": 1, "model_type": model_type, "feature_names": list(FEATURE_NAMES),
            "parameters": parameters, "metadata": metadata}


def describe_representation(name: str, *, vocabulary_size: int | None = None) -> dict:
    if name == "char_ngram_logistic":
        return {"version": "registered-domain-char-tfidf-v1", "type": "character_ngram_tfidf",
                "input": "normalized ASCII registered domain including public/private suffix",
                "feature_count": vocabulary_size, "ngram_range": [2, 5],
                "fit_scope": "training split only", "sublinear_tf": True, "norm": "l2"}
    return {"version": FEATURE_VERSION, "type": "numeric_domain_aggregates",
            "input": "12 numeric statistics of registered-domain label and suffix",
            "feature_count": len(FEATURE_NAMES)}


def split_summary(y: np.ndarray, groups: np.ndarray, indices: np.ndarray) -> dict:
    labels = y[indices]
    return {"rows": len(indices), "domains": len(set(groups[indices])),
            "legitimate": int((labels == 0).sum()), "phishing": int((labels == 1).sum())}


def raw_format_audit(raw: pd.DataFrame) -> dict:
    """Measure source formatting conventions; do not interpret them as truth rules."""
    result = {}
    for label, name in [(1, "legitimate"), (0, "phishing")]:
        urls = raw.loc[raw["label"].eq(label), "URL"].dropna().str.lower()
        result[name] = {
            "rows": len(urls),
            "https_prefix_ratio": float(urls.str.startswith("https://").mean()),
            "https_www_prefix_ratio": float(urls.str.startswith("https://www.").mean()),
            "http_www_prefix_ratio": float(urls.str.startswith("http://www.").mean()),
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=ROOT / "data" / "raw" / CSV_NAME)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "artifacts")
    parser.add_argument("--report", type=Path, default=ROOT / "docs" / "model-report.md")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--trees", type=int, default=80)
    parser.add_argument("--max-depth", type=int, default=10)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--vocabulary-size", type=int, default=30000)
    args = parser.parse_args()
    if not args.csv.exists():
        downloaded = download_dataset(args.csv.parent)
        if downloaded != args.csv.resolve():
            raise ValueError("Specify the canonical downloaded CSV path")
    source_sha = sha256_file(args.csv)
    print("Loading original URLs and labels", flush=True)
    raw = pd.read_csv(args.csv, usecols=["URL", "label"], dtype={"URL": str})
    raw_count = len(raw)
    format_audit = raw_format_audit(raw)
    records = []
    invalid_count = 0
    for row in raw.itertuples(index=False):
        try:
            if pd.isna(row.URL) or row.label not in (0, 1):
                raise ValueError("Missing URL or invalid class label")
            parsed = parse_url(row.URL)
            normalized = parsed["normalized_url"]
            group = parsed["registered_domain"] or parsed["host"]
            records.append((normalized, group, int(1 - row.label)))
        except (ValueError, TypeError, UnicodeError):
            invalid_count += 1
    frame = pd.DataFrame(records, columns=["url", "group", "label"])
    conflicts = frame.groupby("url", sort=False)["label"].nunique()
    conflict_urls = set(conflicts[conflicts > 1].index)
    conflict_rows = int(frame["url"].isin(conflict_urls).sum())
    frame = frame.loc[~frame["url"].isin(conflict_urls)]
    duplicate_rows = int(frame.duplicated("url").sum())
    frame = frame.drop_duplicates("url").sort_values("url", kind="mergesort").reset_index(drop=True)
    if not len(frame):
        raise ValueError("No usable URL observations")
    print(f"Extracting {len(FEATURE_NAMES)} URL features from {len(frame):,} unique observations", flush=True)
    feature_rows = [extract_features(url) for url in frame["url"]]
    X = pd.DataFrame(feature_rows, columns=FEATURE_NAMES).astype(float)
    if not np.isfinite(X.to_numpy()).all():
        raise ValueError("Non-finite features")
    y, groups = frame["label"].to_numpy(), frame["group"].to_numpy()
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=args.seed)
    folds = [index for _, index in splitter.split(X, y, groups)]
    test_index, validation_index = folds[0], folds[1]
    train_index = np.sort(np.concatenate(folds[2:]))
    split = {name: split_summary(y, groups, indices) for name, indices in
             [("train", train_index), ("validation", validation_index), ("test", test_index)]}
    group_sets = [set(groups[index]) for index in [train_index, validation_index, test_index]]
    overlaps = {"train_validation": len(group_sets[0] & group_sets[1]),
                "train_test": len(group_sets[0] & group_sets[2]),
                "validation_test": len(group_sets[1] & group_sets[2])}
    assert not any(overlaps.values()), "Domain leakage detected"
    if any(len(np.unique(y[index])) != 2 for index in [train_index, validation_index, test_index]):
        raise ValueError("Both labels must be represented in every split")
    split.update({"method": "StratifiedGroupKFold(n_splits=5): test=fold0, validation=fold1, train=fold2-4",
                  "seed": args.seed, "domain_overlap": overlaps})
    preprocessing = {"raw_rows": raw_count, "invalid_rows_removed": invalid_count,
                     "conflicting_url_count": len(conflict_urls), "conflicting_rows_removed": conflict_rows,
                     "duplicate_rows_removed": duplicate_rows, "usable_rows": len(frame),
                     "group_column": "registered_domain (host fallback for IP/unknown suffix)",
                     "label_mapping": {"source_0_phishing": 1, "source_1_legitimate": 0}}
    print("Domain-disjoint split:", json.dumps(split, ensure_ascii=False), flush=True)
    candidates = {
        "logistic_regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, random_state=args.seed)),
        "random_forest": RandomForestClassifier(n_estimators=args.trees, max_depth=args.max_depth,
                                                 min_samples_leaf=5, random_state=args.seed, n_jobs=args.jobs),
        "char_ngram_logistic": make_pipeline(
            TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=3,
                            max_features=args.vocabulary_size, sublinear_tf=True, norm="l2", lowercase=True),
            LogisticRegression(C=4.0, max_iter=2000, random_state=args.seed)),
    }
    def model_input(name: str, indices: np.ndarray):
        return groups[indices] if name == "char_ngram_logistic" else X.iloc[indices]
    thresholds = np.linspace(0.0, 1.0, 101)
    results, validation_scores, curves = {}, {}, {}
    for name, model in candidates.items():
        print(f"Training {name}", flush=True)
        model.fit(model_input(name, train_index), y[train_index])
        scores = model.predict_proba(model_input(name, validation_index))[:, 1]
        validation_scores[name] = scores
        curves[name] = [classification_metrics(y[validation_index], scores, float(t)) for t in thresholds]
        best = max(curves[name], key=lambda item: (item["f1"], -item["fpr"], item["recall"], item["threshold"]))
        best = dict(best, roc_auc=float(roc_auc_score(y[validation_index], scores)),
                    average_precision=float(average_precision_score(y[validation_index], scores)))
        results[name] = {"validation": best, "threshold_0_5_validation": classification_metrics(y[validation_index], scores, 0.5)}
        print(f"{name} validation F1={best['f1']:.5f} threshold={best['threshold']:.2f}", flush=True)
    selected = max(results, key=lambda name: (results[name]["validation"]["f1"], -results[name]["validation"]["fpr"]))
    threshold = results[selected]["validation"]["threshold"]
    # Test labels are consulted only after model and threshold selection are frozen.
    print(f"Frozen selection: {selected}, threshold={threshold:.2f}. Evaluating held-out test data.", flush=True)
    for name, model in candidates.items():
        scores = model.predict_proba(model_input(name, test_index))[:, 1]
        metrics = classification_metrics(y[test_index], scores, results[name]["validation"]["threshold"])
        results[name]["test"] = dict(metrics, roc_auc=float(roc_auc_score(y[test_index], scores)),
                                     average_precision=float(average_precision_score(y[test_index], scores)))
    trained_at = datetime.now(timezone.utc).isoformat()
    representations = {
        name: describe_representation(name, vocabulary_size=(len(model.steps[0][1].vocabulary_)
                                                             if name == "char_ngram_logistic" else None))
        for name, model in candidates.items()
    }
    dataset = {"name": "UCI PhiUSIIL Phishing URL (Website)", "page": DATASET_PAGE,
               "license": "CC BY 4.0", "csv_sha256": source_sha}
    metadata = {"selected_model": selected, "threshold": threshold, "trained_at_utc": trained_at,
                "feature_version": FEATURE_VERSION,
                "input_representation": representations[selected],
                "selected_feature_count": representations[selected]["feature_count"],
                "analysis_scope": "registered-domain lexical characteristics (public/private suffix included for text); no page, ordinary host prefix, path, scheme or reputation inspection",
                "development_iteration": 3,
                "evaluation_status": "internal grouped holdout previously inspected in baseline iteration; not an untouched external benchmark",
                "dataset": dataset, "split_counts": {k: split[k] for k in ["train", "validation", "test"]},
                "test_metrics": results[selected]["test"], "validation_metrics": results[selected]["validation"],
                "score_meaning": "Uncalibrated model output for phishing class, not real-world incident probability"}
    bundle = export_model(candidates[selected], selected, metadata)
    parity_indices = np.concatenate([test_index[y[test_index] == label][:500] for label in [0, 1]])
    parity_sample = X.iloc[parity_indices]
    sklearn_scores = candidates[selected].predict_proba(model_input(selected, parity_indices))[:, 1]
    portable_scores = np.asarray([predict_score(row, bundle, domain_text=str(domain))
                                  for row, domain in zip(parity_sample.to_dict(orient="records"), groups[parity_indices], strict=True)])
    max_error = float(np.max(np.abs(sklearn_scores - portable_scores)))
    assert max_error < 1e-10, f"Portable model export mismatch: {max_error}"
    report = {"schema_version": 1, "generated_at_utc": trained_at, "dataset": dataset,
              "preprocessing": preprocessing, "split": split, "raw_format_audit": format_audit,
              "selection": {"model": selected, "threshold": threshold, "metric": "validation F1 (ties: lower FPR)",
                            "test_used_for_selection": False,
                            "development_iteration": 3,
                            "test_partition_previously_inspected": True,
                            "note": "Final bounded development iteration adds domain character patterns after removing formatting shortcuts. Current candidate and threshold selection use validation only; the internal test partition was previously inspected in earlier iterations."},
              "features": list(FEATURE_NAMES), "features_scope": "numeric baseline features; see input_representations for character model vocabulary",
              "input_representations": representations, "selected_feature_count": representations[selected]["feature_count"],
              "models": results,
              "export_validation": {"samples": len(parity_sample), "classes_checked": [0, 1], "max_absolute_score_difference": max_error},
              "environment": {"python": platform.python_version(), "numpy": np.__version__,
                              "pandas": pd.__version__, "scikit_learn": sklearn.__version__, "tldextract": tldextract.__version__},
              "feature_version": FEATURE_VERSION,
              "source_fingerprints": {"features_sha256": sha256_file(ROOT / "linkguard" / "features.py"),
                                      "urltools_sha256": sha256_file(ROOT / "linkguard" / "urltools.py")},
              "training_parameters": {"random_state": args.seed, "random_forest_n_estimators": args.trees,
                                      "random_forest_max_depth": args.max_depth, "random_forest_min_samples_leaf": 5,
                                      "char_ngram_range": [2, 5], "char_min_df": 3,
                                      "char_max_features": args.vocabulary_size, "char_sublinear_tf": True,
                                      "char_logistic_C": 4.0, "char_vocabulary_fit_scope": "train only"}}
    # Capture class/feature distribution to surface easy dataset-specific shortcuts.
    report["feature_means_by_class"] = {
        "legitimate": {k: float(v) for k, v in X.loc[y == 0].mean().items()},
        "phishing": {k: float(v) for k, v in X.loc[y == 1].mean().items()},
    }
    assignments = [f"{hashlib.sha256(frame.iloc[int(i)]['url'].encode()).hexdigest()}:{part}"
                   for part, indices in [("train", train_index), ("validation", validation_index), ("test", test_index)] for i in indices]
    report["split"]["assignment_sha256"] = hashlib.sha256("\n".join(sorted(assignments)).encode()).hexdigest()
    write_json(args.output_dir / "model.json", bundle, compact=True)
    write_json(args.output_dir / "metrics.json", report)
    write_json(args.output_dir / "threshold_curve.json", {"schema_version": 1, "dataset": "validation", "model": selected, "rows": curves[selected]})
    github_domain_score = predict_score(extract_features("https://github.com"), bundle, domain_text="github.com")
    write_report(args.report, report, github_domain_score=github_domain_score)
    print(f"Saved {selected} JSON model and measured reports to {args.output_dir}", flush=True)
    print(json.dumps(results[selected]["test"], ensure_ascii=False), flush=True)


def write_report(path: Path, report: dict, *, github_domain_score: float | None = None) -> None:
    selection = report["selection"]
    lines = ["# LinkGuard 모델 평가 보고서", "", "이 보고서는 scripts/train.py가 실제 실행 결과로 생성했습니다. 수치는 현재 데이터 분할에서 측정한 값이며 인터넷 전체의 탐지 성능을 의미하지 않습니다.", "",
             "**세 번째이자 이번 개발의 마지막 반복에 대한 내부 평가입니다.** URL 전체 특징의 형식 편향을 발견해 등록 도메인 숫자 특징으로 바꾼 뒤, 마지막으로 도메인 문자 패턴을 학습하는 후보를 추가했습니다. 현재 모델과 판정 기준은 검증 데이터로 선택했지만, 이 평가 분할은 앞선 반복에서 이미 확인했으므로 한 번도 보지 않은 외부 검증 데이터라고 주장하지 않습니다.", "",
             f"- 생성 시각(UTC): {report['generated_at_utc']}",
             f"- 원본 CSV SHA-256: `{report['dataset']['csv_sha256']}`",
             f"- 원본 행: {report['preprocessing']['raw_rows']:,} / 사용 행: {report['preprocessing']['usable_rows']:,}",
             f"- 제거: 파싱/라벨 오류 {report['preprocessing']['invalid_rows_removed']:,}, 충돌 라벨 행 {report['preprocessing']['conflicting_rows_removed']:,}, 중복 URL {report['preprocessing']['duplicate_rows_removed']:,}",
             "- 원본 라벨 0(피싱)을 내부 양성 클래스 1로 변환했습니다.",
             "- 숫자 모델은 등록 도메인 이름의 12개 집계 특징을 사용합니다. 문자 모델은 공용/사설 접미사를 포함한 등록 가능 도메인의 문자 2~5개 조각을 TF-IDF로 표현하고 로지스틱 회귀로 학습합니다. 단어장은 학습 데이터에서만 적합했습니다.",
             "- HTTPS 여부, www·일반 하위 호스트, 경로, 쿼리, 프래그먼트, HTML·페이지 접속·외부 평판은 예측 입력에서 제외했습니다.", "",
             "## 데이터 분리", "", "등록 가능 도메인을 그룹으로 묶어 5개 fold를 생성했습니다. fold 0은 최종 평가, fold 1은 검증, 나머지는 학습에 사용했습니다. 스케일러는 학습 데이터에만 적합했습니다.", "",
             "| 분할 | URL 수 | 도메인 수 | 정상 | 피싱 |", "| --- | ---: | ---: | ---: | ---: |"]
    for part in ["train", "validation", "test"]:
        values = report["split"][part]
        lines.append(f"| {part} | {values['rows']:,} | {values['domains']:,} | {values['legitimate']:,} | {values['phishing']:,} |")
    lines += ["", f"- 분할 간 중복 도메인 수: `{report['split']['domain_overlap']}`",
              f"- 분할 재현용 해시: `{report['split']['assignment_sha256']}`", "",
              "## 모델 선택과 성능", "", "각 모델의 판정 기준은 검증 데이터 F1이 최대인 값으로 정했습니다. 모델도 검증 F1로 선택했고, 동점일 때 오탐률이 낮은 모델을 선택했습니다. 이후 선택을 고정하고 최종 평가 데이터를 확인했습니다.", "",
              "| 모델 | 기준 | 검증 F1 | 평가 Precision | 평가 Recall | 평가 F1 | 평가 오탐률 |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for name, values in report["models"].items():
        test, validation = values["test"], values["validation"]
        lines.append(f"| {name} | {validation['threshold']:.2f} | {validation['f1']:.4f} | {test['precision']:.4f} | {test['recall']:.4f} | {test['f1']:.4f} | {test['fpr']:.4f} |")
    if "input_representations" in report:
        lines += ["", "| 모델 | 입력 표현 | 특징 수 |", "| --- | --- | ---: |"]
        for name, representation in report["input_representations"].items():
            lines.append(f"| {name} | {representation['version']} | {representation['feature_count']:,} |")
        lines += ["", "metrics.json의 features 목록은 숫자 모델의 12개 집계 특징입니다. 선택한 문자 모델의 실제 입력 크기는 selected_feature_count와 input_representations에 별도로 기록합니다."]
    test = report["models"][selection["model"]]["test"]
    lines += ["", f"선택 모델: **{selection['model']}**, 기본 기준: **{selection['threshold']:.2f}**", "",
              f"선택 모델 최종 평가: 정상 정분류(TN) {test['tn']:,}, 정상 오탐(FP) {test['fp']:,}, 피싱 미탐(FN) {test['fn']:,}, 피싱 탐지(TP) {test['tp']:,}.", "",
              "## 관측된 수집 데이터 편향", "",
              "공개 데이터의 정상 URL은 모두 `https://www.`로 시작하며 경로와 쿼리가 비어 있습니다. 최초 URL 전체 특징 모델은 이 수집 형식 차이를 강한 단서로 학습해 정상 주소에도 높은 점수를 주었습니다. 해당 모델은 폐기하고 결과만 artifacts/baseline_audit.json에 보존했습니다.", "",
              "현재 주 모델은 스킴·www·일반 하위 호스트·경로·쿼리를 입력에서 제외하고 등록 가능 도메인의 문자열만 사용합니다. 같은 등록 가능 도메인의 경로나 HTTPS 표기가 달라져도 점수가 변하지 않습니다. 두 번째 숫자 모델 결과는 artifacts/domain_numeric_audit.json에 보존했습니다."]
    if "raw_format_audit" in report:
        audit = report["raw_format_audit"]
        lines += ["", f"원본 URL 중 `https://www.` 접두사 비율: 정상 {audit['legitimate']['https_www_prefix_ratio']:.4%}, 피싱 {audit['phishing']['https_www_prefix_ratio']:.4%}."]
    lines += ["", "위 수치는 이번에 사용한 데이터에서 직접 계산했습니다. 실제 서비스 적용 전 다양한 정상 하위 경로와 최신 피싱 URL을 포함한 독립 데이터 평가가 필요합니다.", "",
              "## 해석과 한계", "", "- 공개 수집 데이터의 시점·수집원·URL 형식 편향이 존재할 수 있습니다. 같은 도메인을 나눠 담지 않아도 모든 데이터 편향이 제거되지는 않습니다.",
              "- 도메인 그룹 분리는 신규 도메인에 대한 분할 평가이며, 미래 시점·한국어 문자·최신 공격에 대한 별도 외부 검증은 수행하지 않았습니다.",
              "- 알려진 형식 단서를 제거했어도 도메인 이름·수집원·시점 편향은 남습니다. 외부의 다양한 정상 도메인과 최신 피싱 도메인에 대한 검증이 필요합니다.",
              "- 도메인 문자열만으로는 정상 사이트의 침해된 페이지, 특정 경로의 악성 콘텐츠, 단축 URL 최종 목적지를 탐지할 수 없습니다. 등록 가능 도메인이 같은 링크는 같은 점수를 받습니다.",
              "- 점수는 보정하지 않은 모델 출력입니다. 실제 피해 발생 확률, 신뢰구간, 안전 인증으로 해석할 수 없습니다.",
              "- 공식 도메인 비교는 별도 규칙 결과이며 모델 자체의 개별 예측 설명이 아닙니다.",
              "- 민감도 화면은 검증 데이터에서 미리 계산한 결과를 사용합니다. 최종 평가 데이터로 기준을 재조정하지 않습니다.", "",
              "## 모델 파일 검증", "", f"JSON 내보내기 후 {report['export_validation']['samples']}개 평가 샘플에서 원본 모델과 비교했습니다. 최대 점수 차이: {report['export_validation']['max_absolute_score_difference']:.3g}.",
              "사용자 입력은 외부로 전송하지 않으며, 모델은 저장소에 포함된 JSON에서 읽습니다. pickle 파일을 로드하지 않습니다.", "",
              "## 재현", "", "```bash", "python -m scripts.download_data", "python -m scripts.train --seed 42 --trees 80 --max-depth 10 --jobs 2", "```", "",
              "정확한 환경 버전·추가 지표·특징별 클래스 평균은 artifacts/metrics.json에 기록되어 있습니다.", "",
              "데이터 출처: [UCI PhiUSIIL](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset), CC BY 4.0.", ""]
    if github_domain_score is not None:
        lines += ["## 수동 관찰한 오탐 사례", "",
                  f"정상적인 호스팅 서비스의 도메인인 `github.com`에서도 모델 점수 **{github_domain_score:.6f}**(0~1)가 관찰되었습니다. 이는 정상 서비스 도메인에도 높은 의심 점수가 나올 수 있음을 보여주는 사례입니다.", "",
                  "GitHub의 모든 개별 저장소·호스팅 콘텐츠가 안전하다는 뜻은 아닙니다. 이 수동 사례는 추가 성능 평가나 대표성 있는 벤치마크가 아니며, 모델 선택·재학습·임계값 조정에 사용하지 않았습니다.", ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
