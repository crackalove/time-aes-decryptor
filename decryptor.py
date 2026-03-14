import os
import platform
import time
import sys
import argparse
from ctypes import c_int, cdll, CDLL
from Crypto.Cipher import AES

def get_c_runtime():
    system = platform.system()
    if system == "Windows":
        return cdll.msvcrt
    elif system in ["Linux", "Darwin"]:
        try:
            return CDLL("libc.so.6")
        except OSError:
            return cdll.LoadLibrary("libc.dylib") if system == "Darwin" else cdll.LoadLibrary("libc.so")
    else:
        raise OSError("Неподдерживаемая операционная система")

C_RUNTIME = get_c_runtime()
C_RUNTIME.srand.argtypes = [c_int]
C_RUNTIME.srand.restype = None
C_RUNTIME.rand.argtypes = []
C_RUNTIME.rand.restype = c_int

def generate_key_for_seed(seed, key_length=32):
    C_RUNTIME.srand(seed)
    key = bytearray(key_length)
    for i in range(key_length):
        key[i] = C_RUNTIME.rand() % 256
    return bytes(key)

def unpad_pkcs7(data):
    if len(data) == 0:
        return data
    padding_len = data[-1]
    if 1 <= padding_len <= 16:
        if data[-padding_len:] == bytes([padding_len]) * padding_len:
            return data[:-padding_len]
    return data

def brute_force_decrypt(file_path, search_window_seconds=120, custom_timestamp=None):
    signatures = {
        b'MZ': "Windows Executable (EXE/DLL)",
        b'%PDF': "PDF Document",
        b'\xff\xd8\xff': "JPEG Image",
        b'PK\x03\x04': "ZIP Archive / MS Office (DOCX/XLSX/PPTX)",
        b'\x7fELF': "Linux Binary (ELF)",
        b'\x89PNG\r\n\x1a\n': "PNG Image",
        b'Rar!\x1a\x07': "RAR Archive"
    }

    try:
        if custom_timestamp:
            file_mod_time = custom_timestamp
        else:
            file_mod_time = int(os.path.getmtime(file_path))
            
        print(f"Время модификации файла: {time.ctime(file_mod_time)} (Timestamp: {file_mod_time})")

        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        if len(file_data) < 32:
            print("Файл слишком мал или пуст.")
            return None

        start_time = file_mod_time - search_window_seconds
        end_time = file_mod_time + search_window_seconds
        
        print(f"Начинаю перебор сидов в диапазоне от {start_time} до {end_time}...")
        
        for seed in range(start_time, end_time + 1):
            if seed % 10 == 0:
                print(f"\rПроверяю сид: {seed}   ", end="", flush=True)

            key = generate_key_for_seed(seed)
            
            for aes_mode in [AES.MODE_ECB, AES.MODE_CBC]:
                if aes_mode == AES.MODE_CBC:
                    iv = file_data[:16]
                    encrypted_part = file_data[16:32]
                    cipher = AES.new(key, aes_mode, iv)
                else:
                    encrypted_part = file_data[:16]
                    cipher = AES.new(key, aes_mode)
                
                try:
                    decrypted_part = cipher.decrypt(encrypted_part)
                    
                    format_found = False
                    for sig, file_type in signatures.items():
                        if decrypted_part.startswith(sig):
                            print(f"\n\nНайден сид (timestamp): {seed}")
                            print(f"Определен формат: {file_type}")
                            print(f"AES Ключ (hex): {key.hex()}")
                            format_found = True
                            break
                    
                    if format_found:
                        print("Расшифровываю весь файл...")
                        if aes_mode == AES.MODE_CBC:
                            full_cipher = AES.new(key, aes_mode, iv)
                            decrypted_data = full_cipher.decrypt(file_data[16:])
                        else:
                            full_cipher = AES.new(key, aes_mode)
                            decrypted_data = full_cipher.decrypt(file_data)
                        
                        decrypted_data = unpad_pkcs7(decrypted_data)

                        output_filename = f"DECRYPTED_{os.path.basename(file_path)}"
                        with open(output_filename, 'wb') as f_dec:
                            f_dec.write(decrypted_data)
                            
                        print(f"Файл успешно расшифрован и сохранен как: {output_filename}\n")
                        return decrypted_data
                        
                except Exception:
                    continue
                
        print("\n\nКлюч не найден в заданном временном диапазоне. Возможно, сигнатуры нет в словаре или файл был изменен сильно позже шифрования.")
        return None

    except FileNotFoundError:
        print(f"\nОшибка: файл не найден по пути {file_path}")
        return None
    except Exception as e:
        print(f"\nПроизошла непредвиденная ошибка: {e}")
        return None

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    parser.add_argument("-t", "--timestamp", type=int)
    parser.add_argument("-w", "--window", type=int, default=120)
    args = parser.parse_args()
    
    brute_force_decrypt(args.file, search_window_seconds=args.window, custom_timestamp=args.timestamp)
