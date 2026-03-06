# Importamos los módulos necesarios para criptografía asimétrica (RSA)
# rsa: permite generar y usar claves RSA
# padding: define esquemas de relleno seguros para RSA (OAEP, PSS)

from cryptography.hazmat.primitives.asymmetric import rsa, padding
# Importamos:
# hashes: algoritmos hash criptográficos como SHA-256
# serialization: convertir claves a texto (PEM) y volver a cargarlas
from cryptography.hazmat.primitives import hashes, serialization
# Importamos herramientas de criptografía simétrica
# Cipher: objeto general de cifrado
# algorithms: algoritmos como AES
# modes: modos de operación como CBC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# Backend criptográfico (implementación real basada en OpenSSL)
from cryptography.hazmat.backends import default_backend
# Librería estándar para generar números aleatorios criptográficamente seguros
import secrets
# Librería para codificar bytes como texto ASCII (Base64)
import base64


class ParClaves:
    def __init__(self) -> None:
        #generar una clave privada RSA
        clave_privada = rsa.generate_private_key(
            # Exponente público estándar (valor recomendado y seguro)
            public_exponent=65537,
            # Tamaño de la clave en bits (2048 es el mínimo seguro hoy en día)
            key_size=2048,
            # Motor criptográfico que ejecuta las operaciones
            backend=default_backend()
        )
        #Derivación de la clave pública a partir de la privada
        clave_publica = clave_privada.public_key()

        # clave privada a bytes en formato PEM - PEM (Privacy Enhanced Mail) es un estándar basado en texto (ASCII)
        pem_privada = clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            # PKCS8 es el estándar moderno para claves privadas
            format=serialization.PrivateFormat.PKCS8, #formato interno de la clave privada
            encryption_algorithm=serialization.NoEncryption(),#No aplicar ningún cifrado a la clave privada serializada
        )
        # clave pública a bytes en formato PEM
        pem_publica = clave_publica.public_bytes(
            #PEM
            encoding=serialization.Encoding.PEM,
            # Formato estándar para claves públicas
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


        #bytes PEM a strings UTF-8
        #claves como cadenas de texto
        self.__clave_privada = pem_privada.decode("utf-8")
        self.__clave_publica = pem_publica.decode("utf-8")

    @property
    def clave_privada(self):
            return self.__clave_privada
    @property
    def clave_publica(self):
            return self.__clave_publica


class MensajeCifrado:
    def __init__(self, contenido, firma):
        if contenido is None:
            raise TypeError("contenido no puede ser None")
        if firma is None:
            raise TypeError("firma no puede ser None")
        if not isinstance(contenido, str):
            raise TypeError("contenido debe ser str.")
        if not isinstance(firma, str):
            raise TypeError("firma debe ser str.")

        self.contenido = contenido
        self.firma = firma

class SesionCifrada:
    def __init__(self):
        #par de claves
        self.__par_claves = ParClaves()
        #clave remota
        self.__clave_remota= None
        #sesión comienza como no establecida
        self.establecida = False

    def obtener_clave_publica(self):
        return self.__par_claves.clave_publica

    def reiniciar_sesion(self):
        self.__clave_remota = None
        self.establecida = False

    def establecer_clave_remota(self, clave_remota):

        if clave_remota is None:
            raise ValueError("contenido no puede ser None")
        if not isinstance(clave_remota,str):
            raise TypeError("contenido debe ser string")
        if clave_remota == "":
            raise ValueError("contenido no puede estar vacio")

        #clave pública remota de texto PEM a un objeto usable
        self.__clave_remota = serialization.load_pem_public_key(
            clave_remota.encode(),# a bytes
            backend=default_backend() #objeto RSA público
        )
        #marca sesion como establecida
        self.establecida = True

    def establecida (self):
        return self.establecida

    def cifrar(self, mensaje: str):
        # validaciones
        if not self.establecida:
            raise RuntimeError("sesion no está establecida.")

        if mensaje is None:
            raise TypeError("mensaje no puede ser None.")

        if not isinstance(mensaje, str):
            raise TypeError("mensaje debe ser str.")

        #generar clave simetrica AES-256
        # 32 bytes
        clave_simetrica = secrets.token_bytes(32)
        # cifrado del mensaje con aes-cbc + pkcs7
        # iV aleatorio (16 bytes para AES)
        #Evita que el mismo mensaje cifrado dos veces produzca el mismo resultado
        iv = secrets.token_bytes(16)

        # cifrado de la clave aes con rsa
        # self.__clave_remota = clave pública RSA del receptor
        clave_simetrica_cifrada = self.__clave_remota.encrypt(
            clave_simetrica,
            padding.OAEP(
                # MGF1 (Mask Generation Function) genera máscaras internas para OAEP usando SHA-256
                # Aporta aleatoriedad y seguridad adicional al esquema de padding.
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                # Hash principal que OAEP usa internamente
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(
            algorithms.AES(clave_simetrica),
            modes.CBC(iv),
            backend=default_backend()
        )
        # transformar datos en texto cifrado
        encryptor = cipher.encryptor()

        #mensaje a bytes
        mensaje_bytes = mensaje.encode("utf-8")
        # padding PKCS7  (bloque AES = 16 bytes)
        padding_len = 16 - (len(mensaje_bytes) % 16) # Cuántos bytes faltan para completar el bloque
        mensaje_padded = mensaje_bytes + bytes([padding_len] * padding_len)
        # cifrado AES
        mensaje_cifrado = encryptor.update(mensaje_padded) + encryptor.finalize()

        # paquete = clave AES cifrada con RSA + IV + mensaje cifrado con AES
        paquete = clave_simetrica_cifrada + iv + mensaje_cifrado
        # Base64 para enviarlo como texto
        paquete_b64 = base64.b64encode(paquete).decode("utf-8")

        # firma digital del paquete
        # cargar clave privada propia desde PEM
        clave_privada_obj = serialization.load_pem_private_key(
            self.__par_claves.clave_privada.encode("utf-8"),
            password=None,
            backend=default_backend()
        )

        # firmar el paquete completo con RSA-PSS + SHA-256
        firma = clave_privada_obj.sign(
            paquete,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),  # Generador de máscara con SHA-256
                salt_length=padding.PSS.MAX_LENGTH  # Salt aleatorio máximo para mayor seguridad
            ),
            hashes.SHA256()  # Hash del mensaje antes de firmar
        )

        # firma en Base64 para enviarla como texto
        firma_b64 = base64.b64encode(firma).decode("utf-8")

        # paquete y firma en Base64
        return MensajeCifrado(paquete_b64, firma_b64)

    def verificar_firma(self, mensaje_cifrado: MensajeCifrado):
        if not self.establecida:
            raise RuntimeError("La sesión no está establecida. No se puede verificar la firma.")

        if mensaje_cifrado is None:
            raise TypeError("mensaje_cifrado no puede ser None")

        if not isinstance(mensaje_cifrado, MensajeCifrado):
            raise TypeError("mensaje_cifrado debe ser de tipo MensajeCifrado")

        try:
            # decodificar el paquete recibido (strict mode para detectar alteraciones)
            paquete_recibido = base64.b64decode(
                mensaje_cifrado.contenido,
                validate=True)

            # decodificar la firma recibida (strict mode para detectar alteraciones)
            firma_recibida = base64.b64decode(
                mensaje_cifrado.firma,
                validate=True)

            #obtener la clave pública del remitente.
            #esta clave fue previamente establecida como clave remota.
            clave_publica = self.__clave_remota

            # Verificar firma usando la clave pública del remitente.
            # firma es válida, no se lanza excepción
            clave_publica.verify(
                firma_recibida,
                paquete_recibido,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            # la firma no es valida
            return False

    def descifrar(self, mensaje_cifrado: MensajeCifrado):
        #validaciones
        if not self.establecida:
            raise RuntimeError("La sesión no está establecida. No se puede descifrar el mensaje.")

        if mensaje_cifrado is None:
            raise TypeError("mensaje_cifrado no puede ser None")

        if not isinstance(mensaje_cifrado, MensajeCifrado):
            raise TypeError("mensaje_cifrado debe ser de tipo MensajeCifrado")

        if not self.verificar_firma(mensaje_cifrado):
            raise ValueError("La firma del mensaje no es válida")

        # descifrado

        # decodificar de Base64 el paquete completo
        paquete_recibido = base64.b64decode(mensaje_cifrado.contenido)

        tam_clave = 256

        if len(paquete_recibido) < tam_clave + 16:
            raise ValueError("Paquete inválido o incompleto.")

        # cargar clave privada para descifrar
        clave_privada_obj = serialization.load_pem_private_key(
            self.__par_claves.clave_privada.encode(),
            password=None,
            backend=default_backend()
        )

        # tamaño de la clave AES cifrada (RSA 2048 = 256 bytes)
        tam_clave = 256

        # descifrar la clave AES con nuestra clave privada RSA
        try:
            clave_simetrica_recuperada = clave_privada_obj.decrypt(
            paquete_recibido[:tam_clave],  # primeros 256 bytes = clave AES cifrada
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        except Exception:
            raise ValueError("No se pudo descifrar la clave simétrica.")
        # extraer el IV (16 bytes después de la clave)
        iv_recuperado = paquete_recibido[tam_clave:tam_clave + 16]

        # extraer el mensaje cifrado (resto de bytes)
        mensaje_cifrado_recuperado = paquete_recibido[tam_clave + 16:]

        # crear el descifrador AES
        cipher = Cipher(
            algorithms.AES(clave_simetrica_recuperada),
            modes.CBC(iv_recuperado),
            backend=default_backend(),
        )

        decryptor = cipher.decryptor()

        # descifrar el mensaje
        mensaje_padded = decryptor.update(mensaje_cifrado_recuperado) + decryptor.finalize()

        # eliminar el padding PKCS#7
        mensaje_final = mensaje_padded[:-mensaje_padded[-1]].decode("utf-8")

        # retornar el mensaje en claro
        return mensaje_final