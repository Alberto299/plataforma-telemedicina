import numpy as np
import librosa as lr
import matplotlib.pyplot as plt
import os 
from scipy.signal import hilbert, butter, filtfilt, find_peaks, sosfiltfilt
import numpy as np
from scipy.signal import find_peaks
import sounddevice as sd
from numba import jit

def preprocessAudioFile(pathfile, graph=False, t0=None, t1=None):

    file_path = os.path.expanduser(pathfile)
    x_full, fs = lr.load(file_path, sr=None, mono=True)
    t_full = np.arange(len(x_full)) / fs

    if t0 is not None or t1 is not None:
        start_sample = 0 if t0 is None else int(np.round(t0 * fs))
        end_sample   = len(x_full) if t1 is None else int(np.round(t1 * fs))
        x = x_full[start_sample:end_sample]
        t = np.arange(start_sample, end_sample) / fs
    else:
        x = x_full
        t = t_full

    if graph:
        plt.figure(figsize=(12, 3))
        plt.plot(t, x, label='raw signal')
        plt.xlabel('Time (s)')
        plt.ylabel('Amplitude')
        plt.title('PCG signal (raw)')
        plt.grid(True)
        plt.show()

    return x, t, fs

###########################################################################

def highpass_filter(x, fs, cutoff=20, order=3):
    nyq = 0.5 * fs
    b, a = butter(order, cutoff/nyq, btype='high')
    return filtfilt(b, a, x)

###########################################################################

def bandpass_filter(x, fs, lowcut=25, highcut=150, order=4):
    nyq = 0.5 * fs
    b, a = butter(order, [lowcut/nyq, highcut/nyq], btype='band')
    return filtfilt(b, a, x)

###########################################################################

def spectral_gate_denoise(x, fs, reduction_db=12):
    n_fft = 1024
    hop_length = 256
    
    S = lr.stft(x, n_fft=n_fft, hop_length=hop_length)
    mag, phase = np.abs(S), np.angle(S)

    noise_profile = np.percentile(mag, 20, axis=1, keepdims=True)

    threshold = noise_profile * (10 ** (-reduction_db / 20))
    mask = mag > threshold

    S_denoised = mag * mask * np.exp(1j * phase)

    x_denoised = lr.istft(S_denoised, hop_length=hop_length)
    
    if len(x_denoised) > len(x):
        x_denoised = x_denoised[:len(x)]
    elif len(x_denoised) < len(x):
        x_denoised = np.pad(x_denoised, (0, len(x) - len(x_denoised)))
        
    return x_denoised

###########################################################################

def emphasize_peaks(signal):

    return np.square(signal)

###########################################################################

def compute_hilbert_envelope(x, fs=None, lowpass_cutoff=None, lp_order=4, normalize=True):

    analytic = hilbert(x)
    env = np.abs(analytic)

    if (lowpass_cutoff is not None) and (fs is not None):
        sos = butter(lp_order, lowpass_cutoff, fs=fs, btype='low', output='sos')
        env = sosfiltfilt(sos, env)

    if normalize:
        env = env / (np.max(env) + 1e-12)

    return env

###########################################################################

def compute_shannon_envelope(x, fs=None, lowpass_cutoff=None, lp_order=4, normalize=True):
    eps = 1e-12
    x_norm = x / (np.max(np.abs(x)) + eps)
    
    x_sq = x_norm**2
    
    env = -x_sq * np.log(x_sq + eps)
    
    if (lowpass_cutoff is not None) and (fs is not None):
        sos = butter(lp_order, lowpass_cutoff, fs=fs, btype='low', output='sos')
        env = sosfiltfilt(sos, env)

    if normalize:
        env = env / (np.max(env) + eps)

    return env

###########################################################################

def get_period_double_pass(signal, fs, tolerance=0.15, debug=False):
    
    def find_first_lag(sig_segment):
        
        corr = np.correlate(sig_segment, sig_segment, mode='full')
        corr = corr[len(corr)//2:] 
        
        if corr[0] != 0: corr = corr / corr[0]
            
        min_idx = int(0.3 * fs) 
        max_idx = int(2.0 * fs)
        
        if len(corr) < min_idx: return None, corr
        
        window_end = min(max_idx, len(corr))
        search_window = corr[min_idx:window_end]
        
        if len(search_window) == 0: return None, corr
            
        local_peak_idx = np.argmax(search_window)
        actual_lag = min_idx + local_peak_idx

        return actual_lag, corr

    lag1, corr1 = find_first_lag(signal)
    
    debug_info = {'corr1': corr1, 'lag1': lag1, 'corr2': None, 'lag2': None, 'status': 'Fail Pass 1'}

    if lag1 is None:
        return (None, debug_info) if debug else None

    start_index = 2 * lag1
    
    if len(signal) - start_index < (0.4 * fs):
        debug_info['status'] = 'Signal too short for Pass 2'
        return (None, debug_info) if debug else None
        
    signal_pass2 = signal[start_index:]
    lag2, corr2 = find_first_lag(signal_pass2)
    
    debug_info['corr2'] = corr2
    debug_info['lag2'] = lag2

    if lag2 is None:
        debug_info['status'] = 'Fail Pass 2'
        return (None, debug_info) if debug else None

    diff = abs(lag1 - lag2)
    avg = (lag1 + lag2) / 2
    
    if diff / avg <= tolerance:
        period_seconds = avg / fs
        debug_info['status'] = 'Success'
        return (period_seconds, debug_info) if debug else period_seconds
    else:
        debug_info['status'] = f'Mismatch (T1={lag1}, T2={lag2})'
        return (None, debug_info) if debug else None

###########################################################################

@jit(nopython=True)
def get_max_peak_in_window(arr):
    n = len(arr)
    if n < 3:
        return np.argmax(arr)

    max_val = -np.inf
    max_idx = -1
    found_peak = False

    for i in range(1, n - 1):
        val = arr[i]
        if val > arr[i - 1] and val > arr[i + 1]:
            if val > max_val:
                max_val = val
                max_idx = i
                found_peak = True
    
    if not found_peak:
        return np.argmax(arr)
        
    return max_idx

###########################################################################

@jit(nopython=True)
def find_Best_Peak_JIT(Env_in, period, fs, max_depth=5):
    Env = Env_in.copy()
    depth = 0
    
    while depth < max_depth:
        first_window_len = int(period * fs)
        window = Env[0:first_window_len]
        best_peak_idx = get_max_peak_in_window(window)
        
        s1 = [int(best_peak_idx)]
        currentIdx = best_peak_idx
        
        max_step = int(1.1 * period * fs)
        if max_step == 0: max_step = 1
            
        total_iterations = (len(Env) - currentIdx) // max_step - 1
        check_limit = int(0.2 * total_iterations)
        
        win_start_offset = int(0.9 * period * fs)
        win_end_offset = int(1.1 * period * fs)
        
        sum_amp = float(Env[best_peak_idx])
        count_amp = 1
        
        for i in range(check_limit):
            start_search = currentIdx + win_start_offset
            end_search = currentIdx + win_end_offset
            
            if end_search >= len(Env): break
                
            window = Env[start_search:end_search]
            local_idx = get_max_peak_in_window(window)
            
            absolute_peak_idx = start_search + local_idx
            s1.append(int(absolute_peak_idx))
            
            val = Env[absolute_peak_idx]
            sum_amp += val
            count_amp += 1
            
            currentIdx = absolute_peak_idx

        check_passed = True
        
        if len(s1) > 2:
            first_amp = Env[s1[0]]
            
            sum_rest = sum_amp - first_amp
            count_rest_check = count_amp - 1
            
            if count_rest_check > 0:
                mean_rest = sum_rest / count_rest_check
                
                sum_sq_rest = 0.0
                for k in range(1, len(s1)):
                    v = Env[s1[k]]
                    sum_sq_rest += v * v
                
                var_rest = (sum_sq_rest / count_rest_check) - (mean_rest * mean_rest)
                std_rest = np.sqrt(var_rest) if var_rest > 0 else 0.0
                
                deviation = abs(first_amp - mean_rest)
                
                sigma_limit = 4 * std_rest
                percentage_limit = 0.5 * mean_rest
                
                threshold = max(sigma_limit, percentage_limit)
                
                if deviation > threshold and first_amp > mean_rest:
                    print("hola")
                    check_passed = False
                    depth += 1
                    
                    first_peak_idx = s1[0]
                    left_valley = first_peak_idx
                    while left_valley > 0 and Env[left_valley] > Env[left_valley - 1]:
                        left_valley -= 1
                    right_valley = first_peak_idx
                    while right_valley < len(Env) - 1 and Env[right_valley] > Env[right_valley + 1]:
                        right_valley += 1
                    
                    baseline = 0.5 * (Env[left_valley] + Env[right_valley])
                    for k in range(left_valley, right_valley + 1):
                        Env[k] = baseline
                    continue

        if check_passed:
            remaining_iterations = total_iterations - check_limit
            
            wide_start_offset = int(0.8 * period * fs)
            wide_end_offset = int(1.2 * period * fs)
            
            for i in range(remaining_iterations):
                current_mean = sum_amp / count_amp
                
                start_search = currentIdx + win_start_offset
                end_search = currentIdx + win_end_offset
                
                if end_search >= len(Env): break
                    
                window = Env[start_search:end_search]
                local_idx = get_max_peak_in_window(window)
                candidate_amp = window[local_idx]
                absolute_peak_idx = start_search + local_idx
                
                is_weak = candidate_amp < (0.5 * current_mean)
                
                if is_weak:
                    start_wide = currentIdx + wide_start_offset
                    end_wide = currentIdx + wide_end_offset
                    
                    if end_wide < len(Env):
                        window_wide = Env[start_wide:end_wide]
                        local_idx_wide = get_max_peak_in_window(window_wide)
                        amp_wide = window_wide[local_idx_wide]
                        
                        if amp_wide > candidate_amp:
                            absolute_peak_idx = start_wide + local_idx_wide
                            candidate_amp = amp_wide
                
                s1.append(int(absolute_peak_idx))
                currentIdx = absolute_peak_idx
                
                sum_amp += candidate_amp
                count_amp += 1
            
            return s1
        
    return s1

###################################################################################

@jit(nopython=True)
def find_S2_JIT(s1, Env):
    n = len(s1) - 1
    s2 = np.empty(n, dtype=np.int64)
    
    for i in range(n):
        start_node = s1[i]
        end_node = s1[i + 1]
        
        cycle_len = end_node - start_node
        
        offset_start = int(0.1 * cycle_len) 
        offset_end = int(0.05 * cycle_len)
        
        search_start = start_node + offset_start
        search_end = end_node - offset_end
        
        if search_end > search_start:
            window = Env[search_start:search_end]
            local_idx = get_max_peak_in_window(window)
            
            s2[i] = search_start + local_idx
        else:
            s2[i] = start_node + (cycle_len // 2)
        
    return s2

###########################################################################

@jit(nopython=True)
def verify_S2_Consistency_JIT(s1, s2):
    n = len(s2)
    if n < 2:
        return True, 0.0, 0.0 
    
    sum_sys = 0.0
    sum_sq_sys = 0.0
    
    for i in range(n):
        interval = s2[i] - s1[i]
        sum_sys += interval
        sum_sq_sys += interval * interval
        
    mean_sys = sum_sys / n
    var_sys = (sum_sq_sys / n) - (mean_sys * mean_sys)
    std_sys = np.sqrt(var_sys) if var_sys > 0 else 0.0
    
    cv = std_sys / mean_sys if mean_sys > 0 else 0
    
    is_consistent = cv < 0.15  
    
    return is_consistent, mean_sys, std_sys

###########################################################################

def process_heart_sound(file_path, t0=0, t1=None, plot=False, filter_config=None):
    
    if filter_config is None:
        filter_config = {'lowcut': 25, 'highcut': 200, 'order': 4, 'denoise_db': 15}

    x_raw, t, fs = preprocessAudioFile(file_path, t0=t0, t1=t1, graph=False)
    
    # check if raw signal is silent
    if np.max(np.abs(x_raw)) < 1e-4:
        return None

    # filter Chain
    x_hp = highpass_filter(x_raw, fs, cutoff=20, order=3)
    x_denoised = spectral_gate_denoise(x_hp, fs, reduction_db=filter_config['denoise_db'])
    x_final = bandpass_filter(x_denoised, fs, 
                              lowcut=filter_config['lowcut'], 
                              highcut=filter_config['highcut'], 
                              order=filter_config['order'])
    
    # Dead Signal or Filter Killed Signal 
    max_amp_raw = np.max(np.abs(x_raw))
    max_amp_filt = np.max(np.abs(x_final))
    
    # reject if filtered signal is extremely weak relative to raw or absolute terms
    if max_amp_filt < 0.005 or (max_amp_filt / max_amp_raw < 0.01):
        return None

    x_final_sqrd = emphasize_peaks(x_final)

    # Envelope Calculation
    Env_hilbert = compute_hilbert_envelope(x_final, fs=fs, lowpass_cutoff=20, lp_order=4)
    
    # noise detection
    env_mean = np.mean(Env_hilbert)
    if env_mean > 0.35: 
        return None

    # 4. Period Estimation
    period = get_period_double_pass(Env_hilbert, fs, debug=False)
    if isinstance(period, tuple): period = period[0]
        
    if period is None or period == 0:
        return None

    bpm = 60.0 / period
    
    if bpm > 199.0: 
        return None

    # peak Finding
    s1_idxs_list = find_Best_Peak_JIT(Env_hilbert, period, fs)
    s1_idxs = np.array(s1_idxs_list)
    s2_idxs = find_S2_JIT(s1_idxs, Env_hilbert)

    # validation logic
    is_consistent, mean_sys, std_sys = verify_S2_Consistency_JIT(s1_idxs, s2_idxs)
    
    phys_status = "Skipped" 
    
    # Systole vs Diastole ---
    if len(s2_idxs) > 0 and len(s1_idxs) > 1:
        phys_status = "OK"
        
        avg_systole = mean_sys
        
        diastole_sum = 0.0
        count_dia = 0
        for i in range(len(s2_idxs)):
            if i + 1 < len(s1_idxs):
                diastole_sum += (s1_idxs[i+1] - s2_idxs[i])
                count_dia += 1
        
        avg_diastole = diastole_sum / count_dia if count_dia > 0 else 0
        
        # check Inversion (S1 vs S2 swap)
        if avg_systole > avg_diastole:
            if bpm < 100:
                phys_status = "INVERTED (Swapped)"
                # Swap arrays if needed
                s1_temp = s1_idxs.copy()
                s1_idxs = s2_idxs.copy()
                s2_idxs = s1_temp
            else:
                phys_status = "High HR (Sys > Dia OK)"

    # calculate cycle boundaries
    s1_onsets, s1_offsets = find_peak_boundaries(s1_idxs, Env_hilbert)
    
    # chop into Cycles
    cycles = segment_cycles(x_raw, s1_onsets, fs)

    #quality score
    score = 0
    if is_consistent: score += 20
    if 40 < bpm < 180: score += 10
    if len(s1_idxs) > 3: score += 10
    if "INVERTED" not in phys_status: score += 5

    # 8. Plotting
    if plot:
        plt.figure(figsize=(12, 10))
        
        # Subplot 1: Filtered Signal
        plt.subplot(3, 1, 1)
        plt.plot(t, x_final, color='orange', label=f"Filtered ({filter_config.get('name', 'Custom')})")
        plt.title(f"Heart Sound Analysis (HR: {bpm:.1f} BPM)")
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        # Subplot 2: Envelope & Segmentation
        plt.subplot(3, 1, 2)
        plt.plot(t, Env_hilbert, color='green', label='Envelope')
        
        valid_s1 = s1_idxs[s1_idxs < len(t)]
        valid_s2 = s2_idxs[s2_idxs < len(t)]
        plt.plot(t[valid_s1], Env_hilbert[valid_s1], 'bD', markersize=8, label='S1 Peak')
        plt.plot(t[valid_s2], Env_hilbert[valid_s2], 'rX', markersize=8, label='S2 Peak')
        
        # Mark Onsets
        for onset in s1_onsets:
            if onset < len(t):
                plt.axvline(x=t[onset], color='k', linestyle='--', alpha=0.5)
            
        plt.title(f"Segmentation (S2 Consistent: {is_consistent}, Phys: {phys_status})")
        plt.legend()
        
        # Subplot 3: Cycles
        plt.subplot(3, 1, 3)
        for i, cycle in enumerate(cycles[:3]): # Show first 3 cycles
            t_cycle = np.arange(len(cycle)) / fs
            plt.plot(t_cycle, cycle, alpha=0.7, label=f'Cycle {i+1}')
            
        plt.title("Overlay of First 3 Extracted Cycles")
        plt.legend()
        plt.tight_layout()
        plt.show(block=False)

    # 9. Return Results
    results = {
        's1_idxs': s1_idxs,
        's2_idxs': s2_idxs,
        's1_onsets': s1_onsets,
        's1_offsets': s1_offsets,
        'cycles': cycles,
        't': t,
        'signal_raw': x_raw,
        'signal_filtered': x_final,
        'envelope': Env_hilbert,    # Important for external plotting
        'bpm': bpm,
        'status': {
            's2_consistent': is_consistent,
            'phys_check': phys_status,
        },
        'quality_score': score,     # Added quality score
        'used_config': filter_config
    }
    
    return results

#########################################################################################

def smart_segmentation_recursive(file_path, t0=0, t1=None, plot=False, 
                                 config_level=0):
    configs = [
        # Level 0: Standard 
        {'lowcut': 25, 'highcut': 200, 'order': 4, 'denoise_db': 15, 'name': 'Standard (25-200Hz)'},
        # Level 1: Wide 
        {'lowcut': 20, 'highcut': 500, 'order': 3, 'denoise_db': 10, 'name': 'Wide (20-500Hz)'},
        # Level 2: Low Freq 
        {'lowcut': 15, 'highcut': 150, 'order': 3, 'denoise_db': 15, 'name': 'LowFreq (15-150Hz)'},
        # Level 3: High Freq (Noisy/Weak)
        {'lowcut': 30, 'highcut': 600, 'order': 2, 'denoise_db': 5,  'name': 'HighSensitivity'},
    ]
    
    if config_level >= len(configs):
        print("[Fail] All configurations failed. Returning None.")
        return None

    current_config = configs[config_level]
    print(f"--- Attempt {config_level + 1}: {current_config['name']} ---")
    
    result = process_heart_sound(file_path, t0, t1, plot=False, filter_config=current_config)
    
    is_success = False
    
    if result is not None:
        status = result['status']
        
        consistent_s2 = status['s2_consistent']
        
        bpm = result['bpm']
        valid_hr = 40 <= bpm <= 200
        
        num_peaks = len(result['s1_idxs'])
        has_data = num_peaks >= 3
        
        if consistent_s2 and valid_hr and has_data:
            is_success = True
            print(f"[Success] Locked on with {current_config['name']} (Peaks: {num_peaks}, HR: {bpm:.1f})")
            
        elif config_level == len(configs) - 1:
            if num_peaks > 0:
                is_success = True
                print("[Warning] Accepting imperfect result (Last Resort).")
            else:
                print("[Fail] Last resort found no peaks.")

    if is_success:
        if plot:
            process_heart_sound(file_path, t0, t1, plot=True, filter_config=current_config)
        return result
    else:
        reason = "Unknown"
        if result is None: reason = "Signal Killed"
        elif not has_data: reason = "No Peaks Found"
        elif not consistent_s2: reason = "Inconsistent Pattern"
        elif not valid_hr: reason = f"Invalid HR ({result['bpm']:.1f})"
            
        print(f"[Retry] Config {config_level + 1} failed ({reason}). Recursing...")
        return smart_segmentation_recursive(file_path, t0, t1, plot, config_level + 1)

@jit(nopython=True)
def find_peak_boundaries(peaks, Env):

    n = len(peaks)
    onsets = np.empty(n, dtype=np.int64)
    offsets = np.empty(n, dtype=np.int64)
    
    env_len = len(Env)
    
    for i in range(n):
        peak_idx = peaks[i]
        
        left = peak_idx
        while left > 0:
            if Env[left - 1] > Env[left]:
                break
            left -= 1
        onsets[i] = left
        
        right = peak_idx
        while right < env_len - 1:
            if Env[right + 1] > Env[right]:
                break
            right += 1
        offsets[i] = right
        
    return onsets, offsets

def segment_cycles(signal, onsets, fs):
    cycles = []
    
    for i in range(len(onsets) - 1):
        start_idx = onsets[i]
        end_idx = onsets[i+1]
        
        segment = signal[start_idx:end_idx]
        cycles.append(segment)
        
    return cycles


###############################################
### EJEMPLO DE USO EN CASO DE IMPLEMENTARLO ###
###############################################
"""
import aux_segmentation_method as sp

# 1. Define your file path
file_path = "path/to/your/audio.wav"

# 2. Call the function (plot=False for pure data processing)
# The function automatically handles filtering, envelope extraction, and segmentation.
data = sp.process_heart_sound(file_path, plot=False)

if data:
    # --- SUCCESS ---
    # The 'cycles' key contains a list of numpy arrays, 
    # where each array is one individual heartbeat (S1 start -> Next S1 start).
    cycles = data['cycles']
    fs = 4000  # (Or access data['fs'] if you added that key, otherwise use known fs)

    print(f"Processing Successful!")
    print(f"Heart Rate: {data['bpm']:.1f} BPM")
    print(f"Total Cycles Extracted: {len(cycles)}")

    # Example: Working with the segmented data
    for i, cycle_signal in enumerate(cycles):
        duration = len(cycle_signal) / fs
        print(f"Cycle {i+1}: {len(cycle_signal)} samples ({duration:.3f}s)")

    # You can now pass 'cycles' directly to a machine learning model or statistical analysis
    # e.g., template_beat = np.mean(cycles, axis=0) 

else:
    # --- FAILURE ---
    # Returns None if the signal was too noisy, silent, or had no clear rhythm.
    print("Could not segment the audio file.")
"""
