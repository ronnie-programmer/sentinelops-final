import numpy as np
from ueba.features import event_to_features
from ueba.scoring import score_event, is_anomaly
from ueba.event_generator import generate_normal_event, generate_anomalous_event, USERS


def test_event_to_features_shape():
    event = generate_normal_event("alice.chen")
    features = event_to_features(event)
    assert features.shape == (8,)
    assert all(0.0 <= f <= 1.0 for f in features)


def test_score_without_model_returns_neutral():
    score = score_event("nonexistent_user_xyz", generate_normal_event("nonexistent_user_xyz"))
    assert score == 50


def test_is_anomaly_threshold():
    assert is_anomaly(75) is True
    assert is_anomaly(65) is False
    assert is_anomaly(70) is True


def test_anomalous_event_has_higher_features():
    normal = generate_normal_event("alice.chen")
    anomalous = generate_anomalous_event("alice.chen")
    assert anomalous["hour_of_day"] in [1, 2, 3, 23]  # off-hours
    assert anomalous["is_privileged"] is True


def test_train_and_score():
    """Integration test: train a baseline and verify scoring works."""
    from ueba.models.baseline import train_baseline, load_model
    from ueba.event_generator import generate_baseline_events
    import os
    username = "test_user_ueba"
    events = generate_baseline_events(username, 20)
    result = train_baseline(username, events)
    assert result["status"] == "trained"
    model = load_model(username)
    assert model is not None
    # Clean up artifact
    artifact = result.get("artifact_path", "")
    if artifact and os.path.exists(artifact):
        os.remove(artifact)
