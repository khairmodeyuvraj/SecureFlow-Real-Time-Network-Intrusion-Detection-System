from typing import Dict, Any
from sklearn.model_selection import RandomizedSearchCV
from sklearn.ensemble import RandomForestClassifier


def tune_random_forest(X_train, y_train, n_iter: int = 5, cv: int = 3) -> Dict[str, Any]:
    """Randomized search parameter tuning for Random Forest."""
    param_dist = {
        "n_estimators": [50, 100, 150],
        "max_depth": [10, 20, None],
        "min_samples_split": [2, 5],
    }

    rf = RandomForestClassifier(random_state=42, class_weight="balanced")
    search = RandomizedSearchCV(
        rf,
        param_distributions=param_dist,
        n_iter=n_iter,
        cv=cv,
        scoring="f1",
        random_state=42,
        n_jobs=-1,
    )
    search.fit(X_train, y_train)

    return {
        "best_params": search.best_params_,
        "best_score": float(search.best_score_),
        "best_estimator": search.best_estimator_,
    }
