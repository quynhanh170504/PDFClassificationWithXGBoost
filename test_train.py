from sklearn.ensemble import RandomForestClassifier
from sklearn.datasets import make_classification
import joblib
import onnx
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

# Generate a dataset (replace this with actual malware feature data)
X, y = make_classification(n_samples=1000, n_features=20, n_classes=2, random_state=42)

# Train a RandomForest model
model = RandomForestClassifier(n_estimators=100)
model.fit(X, y)

# Save the model using joblib
joblib.dump(model, 'random_forest_model.pkl')

# Convert and save as ONNX model
initial_type = [('float_input', FloatTensorType([None, X.shape[1]]))]
onnx_model = convert_sklearn(model, initial_types=initial_type)
with open("random_forest_model.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())
