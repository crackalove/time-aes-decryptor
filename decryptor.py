import os
import platform
import time
import sys
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

def generate_key_for_seed(seed, key_length=32):
    c_runtime = get_c_runtime()
    
    c_runtime.srand.argtypes = [c_int]
    c_runtime.srand.restype = None
    c_runtime.rand.argtypes = []
    c_runtime.rand.restype = c_int

    c_runtime.srand(seed)
    
    key = bytearray(key_length)
    for i in range(key_length):
        key[i] = c_runtime.rand() % 256
        
    return bytes(key)

def brute_force_decrypt(file_path, search_window_seconds=120):
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
        file_mod_time = int(os.path.getmtime(file_path))
        print(f"Время модификации файла: {time.ctime(file_mod_time)} (Timestamp: {file_mod_time})")

        with open(file_path, 'rb') as f:
            encrypted_header = f.read(16)
        
        if not encrypted_header or len(encrypted_header) < 16:
            print("Файл слишком мал или пуст.")
            return None

        start_time = file_mod_time - search_window_seconds
        end_time = file_mod_time + search_window_seconds
        
        print(f"Начинаю перебор сидов в диапазоне от {start_time} до {end_time}...")
        
        for seed in range(start_time, end_time + 1):
            if seed % 10 == 0:
                print(f"\rПроверяю сид: {seed}   ", end="", flush=True)

            key = generate_key_for_seed(seed)
            cipher = AES.new(key, AES.MODE_ECB)
            
            try:
                decrypted_header = cipher.decrypt(encrypted_header)
                
                format_found = False
                for sig, file_type in signatures.items():
                    if decrypted_header.startswith(sig):
                        print(f"\n\nНайден сид (timestamp): {seed}")
                        print(f"Определен формат: {file_type}")
                        print(f"AES Ключ (hex): {key.hex()}")
                        format_found = True
                        break
                
                if format_found:
                    print("Расшифровываю весь файл...")
                    with open(file_path, 'rb') as f_enc:
                        encrypted_data = f_enc.read()
                    
                    full_cipher = AES.new(key, AES.MODE_ECB)
                    decrypted_data = full_cipher.decrypt(encrypted_data)
                    
                    padding_len = decrypted_data[-1]
                    if 0 < padding_len <= 16 and decrypted_data.endswith(bytes([padding_len]) * padding_len):
                         decrypted_data = decrypted_data[:-padding_len]

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
    if len(sys.argv) < 2:
        print("Использование: python decryptor.py <путь_к_зашифрованному_файлу>")
        sys.exit(1)
        
    target_file = sys.argv[1]
    brute_force_decrypt(target_file)
