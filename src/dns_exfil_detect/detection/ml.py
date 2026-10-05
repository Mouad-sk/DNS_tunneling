"""RandomForest / XGBoost classifier over window feature vectors."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np

from dns_exfil_detect.models import FEATURE_NAMES, WindowFeatures


class MLClassifier:
    """Load/save a tree ensemble and score windows as P(tunnel)."""

    def __init__(self, estimator: Any | None = None, backend: str = "random_forest") -> None:
        self.estimator = estimator
        self.backend = backend
        self.feature_names: tuple[str, ...] = FEATURE_NAMES

    @property
    def ready(self) -> bool:
        return self.estimator is not None

    def predict_proba(self, window: WindowFeatures) -> float:
        if self.estimator is None:
            return float("nan")
        vector = np.asarray([window.to_vector()], dtype=float)
        proba = self.estimator.predict_proba(vector)[0]
        # class 1 = malicious / tunneling
        if len(proba) == 1:
            return float(proba[0])
        return float(proba[1])

    def feature_importance(self) -> dict[str, float]:
        if self.estimator is None or not hasattr(self.estimator, "feature_importances_"):
            return {}
        values = list(self.estimator.feature_importances_)
        return {name: float(values[i]) for i, name in enumerate(self.feature_names) if i < len(values)}

    def save(self, path: str | Path) -> None:
        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"estimator": self.estimator, "backend": self.backend, "features": self.feature_names}, dest)

    @classmethod
    def load(cls, path: str | Path) -> MLClassifier:
        payload = joblib.load(Path(path))
        if isinstance(payload, dict):
            obj = cls(estimator=payload.get("estimator"), backend=str(payload.get("backend", "random_forest")))
            names = payload.get("features")
            if names:
                obj.feature_names = tuple(names)
            return obj
        return cls(estimator=payload)


def build_estimator(backend: str = "random_forest", random_state: int = 42) -> Any:
    """Construct an unfitted classifier. XGBoost is optional."""
    if backend == "xgboost":
        try:
            from xgboost import XGBClassifier
        except ImportError as exc:
            raise RuntimeError("xgboost is not installed; pip install xgboost") from exc
        return XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="logloss",
            random_state=random_state,
            n_jobs=-1,
        )
    from sklearn.ensemble import RandomForestClassifier

    return RandomForestClassifier(
        n_estimators=300,
        max_depth=12,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1,
    )
