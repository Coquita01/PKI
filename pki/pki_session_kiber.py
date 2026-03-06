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
#AGREGAMOS
# oqs: librería (Open Quantum Safe) que implementa ML-KEM (antes CRYSTALS-Kyber)
# para acordar un secreto compartido; NO cifra el mensaje directo.
import oqs

# HKDF: derivación de claves; convierte el secreto compartido del KEM en una clave AES
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Algoritmo KEM recomendado
KEM_ALG = "ML-KEM-768"


class ParClaves:
    def __init__(self) -> None:
        # generar una clave privada RSA (se conserva para firmas RSA-PSS)
        clave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        clave_publica = clave_privada.public_key()

        # clave privada a bytes en formato PEM
        pem_privada = clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # clave pública a bytes en formato PEM
        pem_publica = clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # bytes PEM a strings UTF-8
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
        # par de claves RSA (se conserva para firmar/verificar firma)
        self.__par_claves = ParClaves()
        #  __clave_remota  CLAVE PUBLICA ML-KEM  del receptor
        self.__clave_remota = None
        #clave pública RSA remota
        self.__clave_remota_rsa = None
        # par de claves KEM propio ML-KEM
        self.__kem = oqs.KeyEncapsulation(KEM_ALG)
        self.__kem_public_key = self.__kem.generate_keypair()  # bytes

        # sesión comienza como no establecida
        self.establecida = False

    def obtener_clave_publica(self):
        # retorna la clave pública RSA para firma
        return self.__par_claves.clave_publica

    def obtener_clave_publica_kem(self):
        return base64.b64encode(self.__kem_public_key).decode("utf-8")

    def reiniciar_sesion(self):
        self.__clave_remota = None
        self.__clave_remota_rsa = None
        self.establecida = False

    # clave_remota_kem_b64: clave publica ML-KEM del receptor (Base64)
    # clave_remota_rsa_pem: clave publica RSA del receptor (PEM) para verificar firma
    def establecer_clave_remota(self, clave_remota):

        if clave_remota is None:
            raise ValueError("contenido no puede ser None")
        if not isinstance(clave_remota, str):
            raise TypeError("contenido debe ser string")
        if clave_remota == "":
            raise ValueError("contenido no puede estar vacio")

        delim = "\n-----DELIM-----\n"
        if delim not in clave_remota:
            raise ValueError(
                "Formato inválido. Debes enviar: KEM_B64 + '\\n-----DELIM-----\\n' + RSA_PEM"
            )

        kem_b64, rsa_pem = clave_remota.split(delim, 1)

        # 1) Guardar clave pública KEM remota
        self.__clave_remota = base64.b64decode(kem_b64.strip(), validate=True)

        # 2) Guardar clave pública RSA remota
        self.__clave_remota_rsa = serialization.load_pem_public_key(
            rsa_pem.encode(),
            backend=default_backend()
        )

        # marca sesión como establecida
        self.establecida = True

    def establecida(self):
        return self.establecida

    # Derivar AES-256 desde el secreto compartido del KEM
    def _derivar_clave_aes_desde_ss(self, shared_secret: bytes) -> bytes:
        # HKDF toma el secreto y produce 32 bytes de clave AES (AES-256)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"SesionCifrada AES-256 key v1",
        ).derive(shared_secret)

    def cifrar(self, mensaje: str):
        # validaciones
        if not self.establecida:
            raise RuntimeError("sesion no está establecida.")
        if mensaje is None:
            raise TypeError("mensaje no puede ser None.")
        if not isinstance(mensaje, str):
            raise TypeError("mensaje debe ser str.")

        with oqs.KeyEncapsulation(KEM_ALG) as kem_sender:
            ct_kem, shared_secret = kem_sender.encap_secret(self.__clave_remota)

        clave_simetrica = self._derivar_clave_aes_desde_ss(shared_secret)

        # IV aleatorio (16 bytes para AES)
        iv = secrets.token_bytes(16)

        cipher = Cipher(
            algorithms.AES(clave_simetrica),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # mensaje a bytes
        mensaje_bytes = mensaje.encode("utf-8")

        # padding PKCS7 (bloque AES = 16 bytes)
        padding_len = 16 - (len(mensaje_bytes) % 16)
        mensaje_padded = mensaje_bytes + bytes([padding_len] * padding_len)

        # cifrado AES
        mensaje_cifrado = encryptor.update(mensaje_padded) + encryptor.finalize()

        # paquete = ct_kem + IV + AES(ciphertext)

        paquete = ct_kem + iv + mensaje_cifrado
        paquete_b64 = base64.b64encode(paquete).decode("utf-8")

        # firma digital del paquete
        clave_privada_obj = serialization.load_pem_private_key(
            self.__par_claves.clave_privada.encode("utf-8"),
            password=None,
            backend=default_backend()
        )

        firma = clave_privada_obj.sign(
            paquete,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        firma_b64 = base64.b64encode(firma).decode("utf-8")
        return MensajeCifrado(paquete_b64, firma_b64)

    def verificar_firma(self, mensaje_cifrado: MensajeCifrado):
        if not self.establecida:
            raise RuntimeError("La sesión no está establecida. No se puede verificar la firma.")
        if mensaje_cifrado is None:
            raise TypeError("mensaje_cifrado no puede ser None")
        if not isinstance(mensaje_cifrado, MensajeCifrado):
            raise TypeError("mensaje_cifrado debe ser de tipo MensajeCifrado")

        try:
            paquete_recibido = base64.b64decode(mensaje_cifrado.contenido, validate=True)
            firma_recibida = base64.b64decode(mensaje_cifrado.firma, validate=True)

            #  self.__clave_remota es KEM
            clave_publica = self.__clave_remota_rsa

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
            return False

    def descifrar(self, mensaje_cifrado: MensajeCifrado):
        # validaciones
        if not self.establecida:
            raise RuntimeError("La sesión no está establecida. No se puede descifrar el mensaje.")
        if mensaje_cifrado is None:
            raise TypeError("mensaje_cifrado no puede ser None")
        if not isinstance(mensaje_cifrado, MensajeCifrado):
            raise TypeError("mensaje_cifrado debe ser de tipo MensajeCifrado")
        if not self.verificar_firma(mensaje_cifrado):
            raise ValueError("La firma del mensaje no es válida")

        # decodificar de Base64 el paquete completo
        paquete_recibido = base64.b64decode(mensaje_cifrado.contenido)

        # el tamaño del ct (ciphertext) depende del KEM
        try:
            tam_clave = self.__kem.details["length_ciphertext"]
        except Exception:
            # fallback por si el binding no expone details
            raise ValueError("No se pudo obtener el tamaño del ciphertext KEM.")

        if len(paquete_recibido) < tam_clave + 16:
            raise ValueError("Paquete inválido o incompleto.")

        # extraer ct_kem (equivalente al bloque que permite recuperar la clave AES)
        ct_kem = paquete_recibido[:tam_clave]

        # extraer IV
        iv_recuperado = paquete_recibido[tam_clave:tam_clave + 16]

        # extraer mensaje cifrado
        mensaje_cifrado_recuperado = paquete_recibido[tam_clave + 16:]

        try:
            shared_secret = self.__kem.decap_secret(ct_kem)
            clave_simetrica_recuperada = self._derivar_clave_aes_desde_ss(shared_secret)
        except Exception:
            raise ValueError("No se pudo recuperar la clave simétrica mediante ML-KEM.")

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

        return mensaje_final