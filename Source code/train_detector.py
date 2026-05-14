import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier
import joblib
import os

def generate_ensemble_models():
    # Number of samples for robust training
    n_samples = 3000
    
    # Feature Names (54 Dimensions)
    feature_names = [
        "Machine", "SizeOfOptionalHeader", "Characteristics", "MajorLinkerVersion",
        "MinorLinkerVersion", "SizeOfCode", "SizeOfInitializedData", "SizeOfUninitializedData",
        "AddressOfEntryPoint", "BaseOfCode", "BaseOfData", "ImageBase", "SectionAlignment",
        "FileAlignment", "MajorOperatingSystemVersion", "MinorOperatingSystemVersion",
        "MajorImageVersion", "MinorImageVersion", "MajorSubsystemVersion", "MinorSubsystemVersion",
        "SizeOfImage", "SizeOfHeaders", "CheckSum", "Subsystem", "DllCharacteristics",
        "SizeOfStackReserve", "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit",
        "LoaderFlags", "NumberOfRvaAndSizes", "SectionsNb", "SectionsMeanEntropy",
        "SectionsMinEntropy", "SectionsMaxEntropy", "SectionsMeanRawsize", "SectionsMinRawsize",
        "SectionMaxRawsize", "SectionsMeanVirtualsize", "SectionsMinVirtualsize",
        "SectionMaxVirtualsize", "ImportsNbDLL", "ImportsNb", "ImportsNbOrdinal", "ExportNb",
        "ResourcesNb", "ResourcesMeanEntropy", "ResourcesMinEntropy", "ResourcesMaxEntropy",
        "ResourcesMeanSize", "ResourcesMinSize", "ResourcesMaxSize", "LoadConfigurationSize",
        "VersionInformationSize"
    ]

    X = []
    y = []

    for _ in range(n_samples):
        is_malicious = np.random.choice([0, 1])
        features = []
        
        # Simulating standard values for legitimate vs malicious
        if is_malicious:
            # Malicious: High entropy, unusual linker versions, fewer exports
            features.extend([332, 224, 258, np.random.randint(2, 14), 0, np.random.randint(50000, 500000), 10000, 0, 4000, 4096, 0, 4194304, 4096, 512, 6, 0, 0, 0, 6, 0, 300000, 1024, 0, 2, 33024])
            features.extend([1048576, 4096, 1048576, 4096, 0, 16, 5, np.random.uniform(6.5, 7.9), np.random.uniform(4.0, 6.0), np.random.uniform(7.5, 7.9)])
            features.extend([np.random.randint(10000, 50000), 512, 100000, 50000, 4096, 200000, 2, np.random.randint(5, 50), np.random.randint(0, 10), np.random.randint(0, 5)])
            features.extend([np.random.randint(1, 15), np.random.uniform(5.5, 7.9), np.random.uniform(3.0, 5.0), np.random.uniform(7.5, 7.9), 1000, 100, 5000, 72, 1])
        else:
            # Benign: Standard linker, typical entropy
            features.extend([332, 224, 258, 12, 0, np.random.randint(10000, 100000), 1000, 0, 4000, 4096, 0, 4194304, 4096, 512, 6, 0, 0, 0, 6, 0, 150000, 1024, 0, 2, 34112])
            features.extend([1048576, 4096, 1048576, 4096, 0, 16, 4, np.random.uniform(3.0, 5.5), np.random.uniform(1.0, 3.5), np.random.uniform(5.0, 6.5)])
            features.extend([np.random.randint(5000, 20000), 512, 50000, 20000, 4096, 100000, 10, np.random.randint(50, 400), 0, 0])
            features.extend([np.random.randint(0, 5), np.random.uniform(2.0, 4.0), np.random.uniform(1.0, 2.0), np.random.uniform(4.0, 5.0), 500, 100, 2000, 72, 1])

        X.append(features)
        y.append(is_malicious)

    X = np.array(X)
    y = np.array(y)

    models_dir = "models"
    if not os.path.exists(models_dir):
        os.makedirs(models_dir)

    # 1. Random Forest Classifier
    rf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42)
    rf.fit(X, y)
    joblib.dump(rf, os.path.join(models_dir, "titanium_rf.pkl"))

    # 2. Gradient Boosting Classifier
    gbm = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=10, random_state=42)
    gbm.fit(X, y)
    joblib.dump(gbm, os.path.join(models_dir, "titanium_gbm.pkl"))

    # 3. Extra Trees Classifier
    et = ExtraTreesClassifier(n_estimators=100, max_depth=15, random_state=42)
    et.fit(X, y)
    joblib.dump(et, os.path.join(models_dir, "titanium_et.pkl"))

    print(f"Ensemble Models Trained: RF, GBM, ET")
    print(f"Feature Vector Dimension: {len(feature_names)}")

if __name__ == "__main__":
    generate_ensemble_models()
