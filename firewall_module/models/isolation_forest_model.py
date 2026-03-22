import joblib
from sklearn.ensemble import IsolationForest

class IsolationForestModel:

    def __init__(self, **kwargs):
        self.model = IsolationForest(**kwargs)

    def train(self, X):
        self.model.fit(X)

    def predict(self, X):
        return self.model.predict(X)

    def decision_function(self, X):
        return self.model.decision_function(X)

    def save_model(self, path):
        joblib.dump(self.model, path)

    def load_model(self, path):
        self.model = joblib.load(path)