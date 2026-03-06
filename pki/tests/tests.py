"""
============================================================
TESTS — Ejercicio: Sistema PKI de Sesión Cifrada
============================================================
Archivo de autocalificación. NO modifiques este archivo.
Ejecutar: python -m unittest discover tests
============================================================
"""

import contextlib
import io
import unittest
from pki_session_Primeraversion import (
    ParClaves,
    SesionCifrada,
    MensajeCifrado,
)


class TestParClaves(unittest.TestCase):
    def setUp(self):
        self.par_claves = ParClaves()

    def test_genera_clave_publica(self):
        self.assertIsNotNone(self.par_claves.clave_publica)

    def test_genera_clave_privada(self):
        self.assertIsNotNone(self.par_claves.clave_privada)

    def test_clave_publica_es_string(self):
        self.assertIsInstance(self.par_claves.clave_publica, str)

    def test_clave_privada_es_string(self):
        self.assertIsInstance(self.par_claves.clave_privada, str)

    def test_clave_publica_no_vacia(self):
        self.assertGreater(len(self.par_claves.clave_publica), 0)

    def test_clave_privada_no_vacia(self):
        self.assertGreater(len(self.par_claves.clave_privada), 0)

    def test_claves_son_diferentes(self):
        publica = self.par_claves.clave_publica
        privada = self.par_claves.clave_privada
        self.assertNotEqual(publica, privada)

    def test_diferentes_instancias_generan_claves_diferentes(self):
        par1 = ParClaves()
        par2 = ParClaves()
        self.assertNotEqual(par1.clave_publica, par2.clave_publica)

    def test_clave_privada_no_expuesta_en_repr(self):
        repr_str = repr(self.par_claves)
        self.assertNotIn(self.par_claves.clave_privada, repr_str)

    def test_clave_privada_no_expuesta_en_str(self):
        str_str = str(self.par_claves)
        self.assertNotIn(self.par_claves.clave_privada, str_str)

    def test_no_acceso_directo_clave_privada_protegida(self):
        """Verifica que no se puede acceder a _clave_privada"""
        with self.assertRaises(AttributeError):
            _ = self.par_claves._clave_privada

    def test_no_acceso_directo_clave_privada_privada(self):
        """Verifica que no se puede acceder a __clave_privada"""
        with self.assertRaises(AttributeError):
            _ = self.par_claves.__clave_privada

    def test_no_acceso_directo_clave_publica_protegida(self):
        """Verifica que no se puede acceder a _clave_publica"""
        with self.assertRaises(AttributeError):
            _ = self.par_claves._clave_publica

    def test_no_acceso_directo_clave_publica_privada(self):
        """Verifica que no se puede acceder a __clave_publica"""
        with self.assertRaises(AttributeError):
            _ = self.par_claves.__clave_publica


class TestMensajeCifrado(unittest.TestCase):
    def setUp(self):
        self.contenido = "datos cifrados"
        self.firma = "firma digital"
        self.mensaje = MensajeCifrado(self.contenido, self.firma)

    def test_constructor_guarda_contenido(self):
        self.assertEqual(self.mensaje.contenido, self.contenido)

    def test_constructor_guarda_firma(self):
        self.assertEqual(self.mensaje.firma, self.firma)

    def test_contenido_vacio_es_valido(self):
        mensaje = MensajeCifrado("", "firma")
        self.assertEqual(mensaje.contenido, "")

    def test_firma_vacia_es_valida(self):
        mensaje = MensajeCifrado("contenido", "")
        self.assertEqual(mensaje.firma, "")

    def test_contenido_es_string(self):
        self.assertIsInstance(self.mensaje.contenido, str)

    def test_firma_es_string(self):
        self.assertIsInstance(self.mensaje.firma, str)

    def test_contenido_none_lanza_typeerror(self):
        with self.assertRaises(TypeError):
            MensajeCifrado(None, "firma")

    def test_firma_none_lanza_typeerror(self):
        with self.assertRaises(TypeError):
            MensajeCifrado("contenido", None)


class TestSesionCifradaCreacion(unittest.TestCase):
    def test_crear_sesion_sin_parametros(self):
        sesion = SesionCifrada()
        self.assertIsNotNone(sesion)

    def test_sesion_genera_par_claves_propio(self):
        sesion = SesionCifrada()
        self.assertIsNotNone(sesion.obtener_clave_publica())

    def test_sesion_clave_publica_es_string(self):
        sesion = SesionCifrada()
        self.assertIsInstance(sesion.obtener_clave_publica(), str)

    def test_sesion_clave_publica_no_vacia(self):
        sesion = SesionCifrada()
        self.assertGreater(len(sesion.obtener_clave_publica()), 0)

    def test_diferentes_sesiones_tienen_claves_diferentes(self):
        sesion1 = SesionCifrada()
        sesion2 = SesionCifrada()
        self.assertNotEqual(
            sesion1.obtener_clave_publica(), sesion2.obtener_clave_publica()
        )


class TestSesionCifradaIntercambioClaves(unittest.TestCase):
    def setUp(self):
        self.sesion_alice = SesionCifrada()
        self.sesion_bob = SesionCifrada()

    def test_establecer_clave_remota_acepta_string(self):
        clave_bob = self.sesion_bob.obtener_clave_publica()
        self.sesion_alice.establecer_clave_remota(clave_bob)

    def test_establecer_clave_remota_none_lanza_valueerror(self):
        with self.assertRaises(ValueError):
            self.sesion_alice.establecer_clave_remota(None)

    def test_establecer_clave_remota_vacia_lanza_valueerror(self):
        with self.assertRaises(ValueError):
            self.sesion_alice.establecer_clave_remota("")

    def test_establecer_clave_remota_no_string_lanza_typeerror(self):
        with self.assertRaises(TypeError):
            self.sesion_alice.establecer_clave_remota(12345)

    def test_sesion_no_establecida_inicialmente(self):
        self.assertFalse(self.sesion_alice.establecida)

    def test_sesion_establecida_tras_intercambio(self):
        clave_bob = self.sesion_bob.obtener_clave_publica()
        self.sesion_alice.establecer_clave_remota(clave_bob)
        self.assertTrue(self.sesion_alice.establecida)

    def test_intercambio_bidireccional(self):
        clave_alice = self.sesion_alice.obtener_clave_publica()
        clave_bob = self.sesion_bob.obtener_clave_publica()

        self.sesion_alice.establecer_clave_remota(clave_bob)
        self.sesion_bob.establecer_clave_remota(clave_alice)

        self.assertTrue(self.sesion_alice.establecida)
        self.assertTrue(self.sesion_bob.establecida)

    def test_no_acceso_directo_clave_simetrica_protegida(self):
        """Verifica que no se puede acceder a _clave_simetrica"""
        with self.assertRaises(AttributeError):
            _ = self.sesion_alice._clave_simetrica

    def test_no_acceso_directo_clave_simetrica_privada(self):
        """Verifica que no se puede acceder a __clave_simetrica"""
        with self.assertRaises(AttributeError):
            _ = self.sesion_alice.__clave_simetrica

    def test_no_acceso_directo_clave_remota_protegida(self):
        """Verifica que no se puede acceder a _clave_remota"""
        with self.assertRaises(AttributeError):
            _ = self.sesion_alice._clave_remota

    def test_no_acceso_directo_clave_remota_privada(self):
        """Verifica que no se puede acceder a __clave_remota"""
        with self.assertRaises(AttributeError):
            _ = self.sesion_alice.__clave_remota

    def test_no_acceso_directo_establecida_protegida(self):
        """Verifica que no se puede acceder a _establecida"""
        with self.assertRaises(AttributeError):
            _ = self.sesion_alice._establecida

    def test_no_acceso_directo_establecida_privada(self):
        """Verifica que no se puede acceder a __establecida"""
        with self.assertRaises(AttributeError):
            _ = self.sesion_alice.__establecida


class TestSesionCifradaCifrado(unittest.TestCase):
    def setUp(self):
        self.sesion_alice = SesionCifrada()
        self.sesion_bob = SesionCifrada()

        # Establecer sesión bidireccional
        clave_alice = self.sesion_alice.obtener_clave_publica()
        clave_bob = self.sesion_bob.obtener_clave_publica()
        self.sesion_alice.establecer_clave_remota(clave_bob)
        self.sesion_bob.establecer_clave_remota(clave_alice)

    def test_cifrar_retorna_mensaje_cifrado(self):
        mensaje = self.sesion_alice.cifrar("Hola Bob")
        self.assertIsInstance(mensaje, MensajeCifrado)

    def test_cifrar_sin_sesion_lanza_runtimeerror(self):
        sesion_sin_conexion = SesionCifrada()
        with self.assertRaises(RuntimeError):
            sesion_sin_conexion.cifrar("mensaje")

    def test_cifrar_texto_vacio(self):
        mensaje = self.sesion_alice.cifrar("")
        self.assertIsInstance(mensaje, MensajeCifrado)

    def test_cifrar_texto_largo(self):
        texto_largo = "A" * 1000
        mensaje = self.sesion_alice.cifrar(texto_largo)
        self.assertIsInstance(mensaje, MensajeCifrado)

    def test_cifrar_none_lanza_typeerror(self):
        with self.assertRaises(TypeError):
            self.sesion_alice.cifrar(None)

    def test_mensaje_cifrado_tiene_contenido(self):
        mensaje = self.sesion_alice.cifrar("Hola")
        self.assertIsNotNone(mensaje.contenido)
        self.assertGreater(len(mensaje.contenido), 0)

    def test_mensaje_cifrado_tiene_firma(self):
        mensaje = self.sesion_alice.cifrar("Hola")
        self.assertIsNotNone(mensaje.firma)
        self.assertGreater(len(mensaje.firma), 0)

    def test_contenido_cifrado_es_diferente_al_original(self):
        texto_original = "Mensaje secreto"
        mensaje = self.sesion_alice.cifrar(texto_original)
        self.assertNotEqual(mensaje.contenido, texto_original)

    def test_cifrar_mismo_texto_dos_veces_genera_contenidos_diferentes(self):
        texto = "Mismo mensaje"
        mensaje1 = self.sesion_alice.cifrar(texto)
        mensaje2 = self.sesion_alice.cifrar(texto)
        # Debido a padding/sal, deberían ser diferentes
        self.assertNotEqual(mensaje1.contenido, mensaje2.contenido)


class TestSesionCifradaDescifrado(unittest.TestCase):
    def setUp(self):
        self.sesion_alice = SesionCifrada()
        self.sesion_bob = SesionCifrada()

        # Establecer sesión bidireccional
        clave_alice = self.sesion_alice.obtener_clave_publica()
        clave_bob = self.sesion_bob.obtener_clave_publica()
        self.sesion_alice.establecer_clave_remota(clave_bob)
        self.sesion_bob.establecer_clave_remota(clave_alice)

    def test_descifrar_retorna_string(self):
        mensaje = self.sesion_alice.cifrar("Hola")
        descifrado = self.sesion_bob.descifrar(mensaje)
        self.assertIsInstance(descifrado, str)

    def test_descifrar_sin_sesion_lanza_runtimeerror(self):
        mensaje = self.sesion_alice.cifrar("Hola")
        sesion_sin_conexion = SesionCifrada()
        with self.assertRaises(RuntimeError):
            sesion_sin_conexion.descifrar(mensaje)

    def test_descifrar_none_lanza_typeerror(self):
        with self.assertRaises(TypeError):
            self.sesion_bob.descifrar(None)

    def test_descifrar_no_mensaje_cifrado_lanza_typeerror(self):
        with self.assertRaises(TypeError):
            self.sesion_bob.descifrar("no soy un mensaje cifrado")

    def test_comunicacion_alice_a_bob(self):
        texto_original = "Hola Bob, soy Alice"
        mensaje = self.sesion_alice.cifrar(texto_original)
        descifrado = self.sesion_bob.descifrar(mensaje)
        self.assertEqual(descifrado, texto_original)

    def test_comunicacion_bob_a_alice(self):
        texto_original = "Hola Alice, soy Bob"
        mensaje = self.sesion_bob.cifrar(texto_original)
        descifrado = self.sesion_alice.descifrar(mensaje)
        self.assertEqual(descifrado, texto_original)

    def test_comunicacion_bidireccional_multiple(self):
        # Alice a Bob
        msg1 = self.sesion_alice.cifrar("Mensaje 1")
        self.assertEqual(self.sesion_bob.descifrar(msg1), "Mensaje 1")

        # Bob a Alice
        msg2 = self.sesion_bob.cifrar("Mensaje 2")
        self.assertEqual(self.sesion_alice.descifrar(msg2), "Mensaje 2")

        # Alice a Bob nuevamente
        msg3 = self.sesion_alice.cifrar("Mensaje 3")
        self.assertEqual(self.sesion_bob.descifrar(msg3), "Mensaje 3")

    def test_descifrar_texto_vacio(self):
        mensaje = self.sesion_alice.cifrar("")
        descifrado = self.sesion_bob.descifrar(mensaje)
        self.assertEqual(descifrado, "")

    def test_descifrar_texto_largo(self):
        texto_largo = "X" * 1000
        mensaje = self.sesion_alice.cifrar(texto_largo)
        descifrado = self.sesion_bob.descifrar(mensaje)
        self.assertEqual(descifrado, texto_largo)

    def test_descifrar_caracteres_especiales(self):
        texto = "¡Hola! ¿Cómo estás? @#$%^&*()"
        mensaje = self.sesion_alice.cifrar(texto)
        descifrado = self.sesion_bob.descifrar(mensaje)
        self.assertEqual(descifrado, texto)

    def test_descifrar_con_clave_incorrecta_lanza_excepcion(self):
        sesion_charlie = SesionCifrada()
        sesion_charlie.establecer_clave_remota(
            self.sesion_alice.obtener_clave_publica()
        )

        mensaje = self.sesion_alice.cifrar("Secreto")

        # Charlie no debería poder descifrar un mensaje de Alice a Bob
        with self.assertRaises((ValueError, RuntimeError)):
            sesion_charlie.descifrar(mensaje)


class TestSesionCifradaVerificacionFirma(unittest.TestCase):
    def setUp(self):
        self.sesion_alice = SesionCifrada()
        self.sesion_bob = SesionCifrada()

        clave_alice = self.sesion_alice.obtener_clave_publica()
        clave_bob = self.sesion_bob.obtener_clave_publica()
        self.sesion_alice.establecer_clave_remota(clave_bob)
        self.sesion_bob.establecer_clave_remota(clave_alice)

    def test_verificar_firma_mensaje_valido_retorna_true(self):
        mensaje = self.sesion_alice.cifrar("Mensaje auténtico")
        self.assertTrue(self.sesion_bob.verificar_firma(mensaje))

    def test_verificar_firma_sin_sesion_lanza_runtimeerror(self):
        mensaje = self.sesion_alice.cifrar("Mensaje")
        sesion_sin_conexion = SesionCifrada()
        with self.assertRaises(RuntimeError):
            sesion_sin_conexion.verificar_firma(mensaje)

    def test_verificar_firma_none_lanza_typeerror(self):
        with self.assertRaises(TypeError):
            self.sesion_bob.verificar_firma(None)

    def test_verificar_firma_mensaje_alterado_retorna_false(self):
        mensaje = self.sesion_alice.cifrar("Original")
        # Alterar el contenido
        mensaje_alterado = MensajeCifrado(mensaje.contenido + "X", mensaje.firma)
        self.assertFalse(self.sesion_bob.verificar_firma(mensaje_alterado))

    def test_verificar_firma_firma_alterada_retorna_false(self):
        mensaje = self.sesion_alice.cifrar("Original")
        # Alterar la firma
        mensaje_alterado = MensajeCifrado(mensaje.contenido, mensaje.firma + "X")
        self.assertFalse(self.sesion_bob.verificar_firma(mensaje_alterado))

    def test_verificar_firma_de_otro_emisor_retorna_false(self):
        sesion_charlie = SesionCifrada()
        sesion_charlie.establecer_clave_remota(self.sesion_bob.obtener_clave_publica())

        mensaje = sesion_charlie.cifrar("De Charlie")
        # Bob espera mensajes de Alice, no de Charlie
        self.assertFalse(self.sesion_bob.verificar_firma(mensaje))


class TestSesionCifradaIntegracion(unittest.TestCase):
    def test_tres_participantes_comunicacion(self):
        alice = SesionCifrada()
        bob = SesionCifrada()
        charlie = SesionCifrada()

        # Alice y Bob establecen sesión
        alice.establecer_clave_remota(bob.obtener_clave_publica())
        bob.establecer_clave_remota(alice.obtener_clave_publica())

        # Alice a Bob (antes de que Bob hable con Charlie)
        msg_alice = alice.cifrar("Para Bob de Alice")
        self.assertEqual(bob.descifrar(msg_alice), "Para Bob de Alice")

        # Bob y Charlie establecen sesión
        bob.establecer_clave_remota(charlie.obtener_clave_publica())
        charlie.establecer_clave_remota(bob.obtener_clave_publica())

        # Bob a Charlie
        msg_bob = bob.cifrar("Para Charlie de Bob")
        self.assertEqual(charlie.descifrar(msg_bob), "Para Charlie de Bob")

    def test_flujo_completo_con_verificacion(self):
        alice = SesionCifrada()
        bob = SesionCifrada()

        # Intercambio de claves
        alice.establecer_clave_remota(bob.obtener_clave_publica())
        bob.establecer_clave_remota(alice.obtener_clave_publica())

        # Alice envía mensaje
        texto = "Información confidencial"
        mensaje = alice.cifrar(texto)

        # Bob verifica firma
        self.assertTrue(bob.verificar_firma(mensaje))

        # Bob descifra
        descifrado = bob.descifrar(mensaje)
        self.assertEqual(descifrado, texto)

    def test_reinicio_sesion(self):
        alice = SesionCifrada()
        bob = SesionCifrada()

        # Primera sesión
        alice.establecer_clave_remota(bob.obtener_clave_publica())
        bob.establecer_clave_remota(alice.obtener_clave_publica())

        msg1 = alice.cifrar("Mensaje 1")
        self.assertEqual(bob.descifrar(msg1), "Mensaje 1")

        # Bob genera nuevas claves y establece nueva sesión
        bob_nuevo = SesionCifrada()
        alice.establecer_clave_remota(bob_nuevo.obtener_clave_publica())
        bob_nuevo.establecer_clave_remota(alice.obtener_clave_publica())

        # Nueva comunicación
        msg2 = alice.cifrar("Mensaje 2")
        self.assertEqual(bob_nuevo.descifrar(msg2), "Mensaje 2")


class TestSesionCifradaSeguridad(unittest.TestCase):
    def test_no_reutilizacion_claves_simetricas(self):
        """Verifica que cada sesión usa claves simétricas únicas"""
        alice = SesionCifrada()
        bob1 = SesionCifrada()
        bob2 = SesionCifrada()

        alice.establecer_clave_remota(bob1.obtener_clave_publica())
        alice.establecer_clave_remota(bob2.obtener_clave_publica())

        # Los mensajes cifrados para diferentes receptores deben ser diferentes
        msg1 = alice.cifrar("mismo texto")
        # Necesitaríamos reiniciar la sesión de alice para bob2
        # Este test verifica que el diseño soporta múltiples receptores

    def test_mensaje_no_puede_ser_descifrado_sin_clave_correcta(self):
        alice = SesionCifrada()
        bob = SesionCifrada()
        eve = SesionCifrada()  # Atacante

        alice.establecer_clave_remota(bob.obtener_clave_publica())
        bob.establecer_clave_remota(alice.obtener_clave_publica())

        mensaje = alice.cifrar("Secreto")

        # Eve no puede descifrar sin establecer sesión con Alice
        with self.assertRaises((RuntimeError, ValueError)):
            eve.descifrar(mensaje)


class TestVulnerabilidadFirmaIgnorada(unittest.TestCase):
    def test_descifrar_ignora_firma_vacia(self):
        """Verifica que descifrar permite mensajes sin firma (vulnerabilidad)"""
        alice = SesionCifrada()
        bob = SesionCifrada()

        alice.establecer_clave_remota(bob.obtener_clave_publica())
        bob.establecer_clave_remota(alice.obtener_clave_publica())

        mensaje = alice.cifrar("Mensaje secreto")
        mensaje.firma = ""  # Eliminamos la firma

        # Esto debería fallar porque la firma es obligatoria
        with self.assertRaises(ValueError):
            bob.descifrar(mensaje)

if __name__ == "__main__":
    import __main__

    suite = unittest.TestLoader().loadTestsFromModule(__main__)
    with io.StringIO() as buf:
        with contextlib.redirect_stdout(buf):
            unittest.TextTestRunner(stream=buf, verbosity=2).run(suite)
        print(buf.getvalue())