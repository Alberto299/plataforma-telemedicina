# train.py
import os
import numpy as np
import librosa
import joblib
import warnings
from scipy.signal import butter, filtfilt, find_peaks
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore")

# ==========================================
# CLASE DE PROCESAMIENTO DE SEÑAL (Similar a tu MATLAB)
# ==========================================
class HeartSignalProcessor:
    def __init__(self, fs=2000):
        self.target_fs = fs  # Frecuencia de muestreo objetivo

    def preprocess_audio(self, file_path, duration=5):
        """
        0.1 - 0.4: Carga, mono, normalización y recorte
        """
        # Cargar audio (librosa convierte a mono y normaliza a -1,1 por defecto)
        try:
            x, fs = librosa.load(file_path, sr=self.target_fs, duration=duration)
        except Exception as e:
            print(f"Error leyendo {file_path}: {e}")
            return None, None

        # 0.3 Normalizar estrictamente a [-1, 1] (como en tu Matlab)
        x = (x - np.min(x)) / (np.max(x) - np.min(x) + 1e-8)
        x = x * 2 - 1
        return x, fs

    def compute_shannon_envelope(self, x, fs):
        """
        1.1 - 2.2: Envolvente de Shannon y Filtro Pasa Bajas (LPF)
        """
        # 1.1 Probabilidad normalizada
        p = np.abs(x)
        p = p / (np.max(p) + 1e-8)

        # 1.2 Energía de Shannon (-p * log(p))
        E = -p * np.log10(p + 1e-8)

        # 1.3 Estandarización
        E_z = (E - np.mean(E)) / (np.std(E) + 1e-8)
        # Normalizar a [0, 1]
        Env0 = (E_z - np.min(E_z)) / (np.max(E_z) - np.min(E_z) + 1e-8)

        # 2.1 LPF (Filtro Butterworth)
        fc = 15  # Corte en Hz (ligeramente ajustado para Python)
        nyq = 0.5 * fs
        b, a = butter(4, fc / nyq, btype='low')
        Env = filtfilt(b, a, Env0)

        # 2.2 Normalización final
        Env = (Env - np.min(Env)) / (np.max(Env) - np.min(Env) + 1e-8)
        
        return Env

    def segment_cycles(self, Env, fs):
        """
        5.1 - 5.3: Segmentación basada en umbrales y duración (Reemplaza lógica de triángulos)
        Esta versión es más robusta en Python que la geometría de triángulos pura.
        """
        # Umbral adaptativo (similar a tu mean * 1.1)
        threshold = np.mean(Env) * 1.1
        
        # Encontrar regiones por encima del umbral
        is_high = Env > threshold
        # Detectar cambios de estado (flancos)
        diff_sig = np.diff(is_high.astype(int))
        starts = np.where(diff_sig == 1)[0]
        ends = np.where(diff_sig == -1)[0]

        # Asegurar consistencia de tamaños
        if len(starts) == 0 or len(ends) == 0:
            return []
        if ends[0] < starts[0]: ends = ends[1:]
        if starts[-1] > ends[-1]: starts = starts[:-1]

        cycles = []
        min_rr = int(0.30 * fs)
        max_rr = int(1.50 * fs)
        
        # Lógica simple: Un ciclo es el intervalo entre dos picos principales de energía
        # Para simplificar vs Matlab: Tomamos picos prominentes como centros de S1/S2
        peaks, _ = find_peaks(Env, height=threshold, distance=int(0.15*fs))
        
        # Calcular diferencias entre picos (intervalos RR candidatos)
        if len(peaks) < 2:
            return []

        # Segmentar ventanas alrededor de los picos para MFCC
        # En lugar de buscar ciclos exactos S1-S2-S1, cortamos ventanas de interés
        # que contienen la información cardíaca relevante.
        cycle_regions = []
        
        # Aproximación: usar ventanas de 0.5s centradas en picos altos
        window_size = int(0.5 * fs) 
        
        for p in peaks:
            start = max(0, p - window_size // 2)
            end = min(len(Env), p + window_size // 2)
            if (end - start) > min_rr:
                cycle_regions.append((start, end))
                
        return cycle_regions

    def extract_features(self, x, fs, cycles):
        """
        Bloque 5: Extracción de MFCCs (Promedio y Desviación Estándar)
        """
        features_list = []
        
        for (start, end) in cycles:
            segment = x[start:end]
            
            if len(segment) < 512: continue # Ignorar muy cortos

            # Extraer MFCC
            mfccs = librosa.feature.mfcc(y=segment, sr=fs, n_mfcc=13, n_fft=2048, hop_length=512)
            
            # Calcular estadísticas (Media y Std)
            mfcc_mean = np.mean(mfccs, axis=1)
            mfcc_std = np.std(mfccs, axis=1)
            
            # Concatenar vector de características (13 medias + 13 stds = 26 features)
            feat_vec = np.concatenate((mfcc_mean, mfcc_std))
            features_list.append(feat_vec)
            
        return np.array(features_list)
    
    
# --- Lógica de Entrenamiento ---
if __name__ == "__main__":
    data_folder = 'data' # Asegúrate de que esta carpeta exista y tenga audios
    print("Entrenando modelo...")
    
    processor = HeartSignalProcessor()
    features, labels = [], []
    
    if not os.path.exists(data_folder):
        print("Error: No existe la carpeta 'data'")
        exit()

    for f in os.listdir(data_folder):
        if not (f.lower().endswith('.mp3') or f.lower().endswith('.wav')): continue
        label = "Normal" if "normal" in f.lower() else "Murmur" if "murmur" in f.lower() or "soplo" in f.lower() else "Click" if "click" in f.lower() else "Unknown"
        if label == "Unknown": continue
        
        x, fs = processor.preprocess_audio(os.path.join(data_folder, f))
        if x is None: continue
        Env = processor.compute_shannon_envelope(x, fs)
        cycles = processor.segment_cycles(Env, fs)
        feats = processor.extract_features(x, fs, cycles)
        
        for feat in feats:
            features.append(feat)
            labels.append(label)
            
    if not features:
        print("No se encontraron datos válidos.")
        exit()

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(features, labels)
    joblib.dump(clf, 'heart_sound_model.pkl')
    print("✅ Modelo guardado como 'heart_sound_model.pkl'")