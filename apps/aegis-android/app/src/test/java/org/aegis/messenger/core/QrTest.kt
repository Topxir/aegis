package org.aegis.messenger.core

import org.junit.Assert.assertEquals
import org.junit.Test

/** Module-for-module agreement with the Rust qrcode crate used by the desktop client. */
class QrTest {
    private fun rows(c: Qr.Code): String =
        (0 until c.size).joinToString("\n") { y -> (0 until c.size).joinToString("") { x -> if (c[x, y]) "1" else "0" } }

    private val inputs = listOf(
        Text.utf8("hi"),
        Text.utf8(Invite.link(ByteArray(32) { 0x11 })),
        ByteArray(120) { it.toByte() },
        ByteArray(175) { (it * 7).toByte() },
    )

    /** SHA-256 of the rows for masks 0 to 7, per input. */
    private val expected = listOf(
        listOf(
            "043e4c6b95be73010f0355a174ee67fb19b6c12b3996de0af1b42a405b437733",
            "275aae7bf9dbc910184e7751b216998633ea286f2d882241404b9bd036477d37",
            "81240590f3a630b03aa70a8aaf521ec30c4911af3307da27eeb2126afcb5b39a",
            "38bf539942cd0442d9f03b87193a15b05afb7b00bca71d8da124578557bfd04b",
            "f63a5e37bcf261355f4bed4ea9afe959c078567cc8b7e29fd3b0f7e8113fd99d",
            "add69b2b9199b2dabe94f129dcb57cde64b34d8b8414589e6d58c2f18998d942",
            "4946133694c71c9e60c7a874d47de433bbf22e4b853cca35181b3cc47968bfc8",
            "80a9f3b98d70bedc58f278de892068eaf221d8ae1c4548e8bd4cfd65739da6fd",
        ),
        listOf(
            "41f5383e7db16dce6fb8313b6a605cdc969f5fd7129b7f5037d2edafb340a276",
            "66c722d8afdcf475ac61af2f065805f9f570a3d164a11082e3a0c042a743cff6",
            "df8283f38397096c8cd0c0acda8454325d7bc0468716a4407ba0456d3c12752b",
            "683a0e154e005a39a77c354cb532e519250c17c658a985b9958c32433205f7f5",
            "217b592d32eab6460fd90677dca70ac4f762cffa7cd192bb8d4f568713543366",
            "4db216a0d138e96d29b86ca5bbd8857027b7207399a6c560a71b6cd2a7f4b08a",
            "7be676d64ebd5e85584ee101641b0188007e9d428fc68df0408a0e581f0800f3",
            "94a62bf7b522333a1479f96891006ede3bb5b4c8dfb0a86544fbea587e486183",
        ),
        listOf(
            "a99f6412eadb0ed00433d59d270a8c238984ad44cb3b8e42d9cc19a5e586a52b",
            "d71dc765a7e8656a02e680a8db7eaf9853fe0fc2897e08086b9505063aecb5b7",
            "159b22f724acb4a973e07ec45058f68048da8d1cb9aea335e721fd293d918599",
            "483c99a0a5020b385839f10d0bbe7cdf5f4a93df3ebbc663b406d43060b9e811",
            "a240e7371bbefebae9ee5b06dbade6da5ada4f1e31a8174034750fe1e7212958",
            "1d12e9c6220b7eb5c29ab602b99f52b41042c1c87ed3627d0bb4e2a6bcc3f2d5",
            "a49255999abedf4f999393419a7f51d204a025f050d468d086173ef62533e276",
            "427a9b20a0bdded417f158df384feeb1fa3345451f9c0f9c8fe19909c359318d",
        ),
        listOf(
            "cf747ae18d969325c489ce9c53c1c210249afdd83e763fdf951d02daca116406",
            "6e9a242802b4ec114bd05dab736f8fd2846ba973eb412e01e64c6cafebdceec5",
            "8335fe05004e50b9ec115b067924cbb2abe968f0ac0d6c18ab9844a8f5e4bec9",
            "e4b4b03d5621711a8fdd60abf1c93f9d3468e3df803100d2dfb5373e5235e6d4",
            "b6cc587da304e22ac15e412576dba08dac0226b0da49981dcbf15ab7762c9cb3",
            "d3dc899c94277f9122b6993ec06045dc0bbf221223284178b569421c50f1cbcf",
            "527ef6694d4c5913c98a0c5e3c481594879ccfb61ee014ea202640eae71363db",
            "88a9478d4e427cc95d9f52ac18b877141d6ae0cf3b00ee59d8078f03c111b3d7",
        ),
    )

    @Test
    fun everyMaskMatchesTheReference() {
        for ((n, data) in inputs.withIndex()) for (mask in 0..7) {
            assertEquals("input $n mask $mask", expected[n][mask], Hex.encode(Crypto.sha256(Text.utf8(rows(Qr.encode(data, mask))))))
        }
    }

    @Test
    fun theLinkFitsVersionFive() {
        assertEquals(37, Qr.encode(inputs[1]).size)
    }
}
